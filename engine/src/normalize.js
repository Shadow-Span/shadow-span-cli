// AppSec result normalization — pure functions, no I/O, no deps.
//
// Each engine wrapper (src/engines/*) produces the tool's raw JSON; the
// normalizers here flatten that into the unified AppSecFinding row shape
// (packages/db/prisma/schema.prisma#AppSecFinding). Severity is normalized
// to the shared FindingSeverity enum: CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
// (note: UNKNOWN, not INFO — reuse, don't fork).
//
// SECURITY (gitleaks): the `Secret` and `Match` fields from gitleaks output
// are NEVER copied into a normalized finding. Only rule id, file, line,
// commit sha and non-sensitive metadata survive normalization — storing the
// leaked value would turn our own DB into a secret store.

// Generated IaC fix corpus — Aqua trivy-checks' canonical remediated example per
// check (290 across AWS/Azure/GCP/+). Static data, no I/O. Hand-verified
// overrides below (K8s/Docker/Bicep) take precedence. Regenerate via
// scripts/gen-iac-fixes.mjs.
import { IAC_FIX_GENERATED } from './iac-fixes.generated.js';

export const FINDING_TYPES = Object.freeze({
  SAST: 'SAST', // ast-grep (MIT) + our own rule packs — Phase 2, LIVE
  SCA: 'SCA', // osv-scanner — Phase 1, LIVE
  IAC: 'IAC', // trivy config (Apache-2.0) — Phase 2, LIVE
  SECRET: 'SECRET', // gitleaks — Phase 1, LIVE
  SBOM_VULN: 'SBOM_VULN', // trivy sbom — Phase 2
  DAST: 'DAST', // Nuclei running-app scan (Phase 1 DAST, LIVE) → OWASP ZAP later.
  //              URL/param-scoped (no lockfile/file); identityKey branch is
  //              DAST:<templateId>:<matchedUrl-no-query>:<matcherName>.
  CICD: 'CICD', // CI/CD pipeline posture — GitHub Actions workflow misconfigs
  //              (script injection, unpinned actions, pull_request_target,
  //              broad permissions). File+line scoped; default identityKey branch.
  CONTAINER: 'CONTAINER', // Dockerfile base-image vulns via `trivy image`. Image+pkg
  //              scoped (Dockerfile FROM line churns) — dedicated identityKey branch.
  LICENSE: 'LICENSE', // SBOM dependency-license policy violations (see license-policy.js).
  //              No file — purl-scoped identityKey LICENSE:<ruleId>:<purl>.
  MALWARE: 'MALWARE', // Known-malicious dependency — OSV malicious-packages (MAL-*),
  //              compromised/typosquat/install-script malware. Always CRITICAL,
  //              never auto-suppressed. Package-scoped identityKey
  //              MALWARE:<osvId>:<ecosystem>:<pkg>.
});

/** OSV malicious-packages advisories use the MAL- namespace. A vuln is malware if
 *  its id OR any alias starts with MAL-. */
export function isMalwareAdvisory(vuln) {
  if (!vuln) return false;
  const ids = [vuln.id, ...(Array.isArray(vuln.aliases) ? vuln.aliases : [])];
  return ids.some((x) => typeof x === 'string' && x.toUpperCase().startsWith('MAL-'));
}

const SEVERITY_WORDS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  MODERATE: 'MEDIUM',
  LOW: 'LOW',
};

/** Map a severity word from any engine to FindingSeverity. */
export function normalizeSeverityWord(word) {
  if (!word || typeof word !== 'string') return 'UNKNOWN';
  return SEVERITY_WORDS[word.trim().toUpperCase()] || 'UNKNOWN';
}

/** Standard CVSS v3 bucket thresholds (same as NVD qualitative ratings). */
export function cvssScoreToSeverity(score) {
  const n = Number(score);
  if (!Number.isFinite(n) || n <= 0) return 'UNKNOWN';
  if (n >= 9.0) return 'CRITICAL';
  if (n >= 7.0) return 'HIGH';
  if (n >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/**
 * Stable per-(org, repo) fingerprint — the @@unique upsert key. Shapes are
 * documented on the schema model; keep both in sync.
 */
export function buildIdentityKey(f) {
  if (f.type === FINDING_TYPES.MALWARE) {
    // Package-scoped — the offending package is the identity, independent of which
    // lockfile surfaced it. Mirrors the SCA shape.
    return `MALWARE:${f.ruleId}:${f.packageEcosystem || ''}:${f.packageName || ''}`;
  }
  if (f.type === FINDING_TYPES.SCA || f.type === FINDING_TYPES.SBOM_VULN) {
    // Lockfile line numbers churn on every dependency bump — exclude them so
    // an unrelated `npm install` doesn't re-open every SCA finding as "new".
    return `${f.type}:${f.ruleId}:${f.packageEcosystem || ''}:${f.packageName || ''}`;
  }
  if (f.type === FINDING_TYPES.SECRET && f.fingerprint) {
    // gitleaks Fingerprint = commit:file:rule:line — stable across re-scans
    // because git history is immutable.
    return `SECRET:${f.fingerprint}`;
  }
  if (f.type === FINDING_TYPES.CONTAINER) {
    // Image + package scoped — the Dockerfile FROM line number churns on edits,
    // so it's excluded (mirrors the SCA lockfile-line rationale).
    return `CONTAINER:${f.ruleId}:${f.dockerImage || ''}:${f.packageName || ''}`;
  }
  if (f.type === FINDING_TYPES.DAST) {
    // URL/param-scoped. Strip the query string so volatile params (cache-busters,
    // session ids) don't re-open the same finding every scan; matcherName
    // distinguishes multiple matches of one template on the same URL.
    const url = stripQuery(f.matchedUrl || f.targetUrl || '');
    return `DAST:${f.ruleId}:${url}:${f.matcherName || ''}`;
  }
  return `${f.type}:${f.ruleId}:${f.file || ''}:${f.line ?? ''}`;
}

const MAX_DESCRIPTION = 2000;

function clip(s, max = MAX_DESCRIPTION) {
  if (!s) return '';
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/**
 * Normalize `osv-scanner --format json` output (v2.x; v1.x shape is
 * compatible for the fields we read).
 *
 * Shape: { results: [{ source: { path }, packages: [{ package: { name,
 * version, ecosystem }, vulnerabilities: [OSV...], groups: [{ ids, aliases,
 * max_severity }] }] }] }
 *
 * One AppSecFinding per (package, OSV id). Severity resolution order:
 *   1. group max_severity (numeric CVSS score string) → bucket
 *   2. OSV database_specific.severity word
 *   3. UNKNOWN
 */
export function normalizeOsvResults(json, { repoRoot = '' } = {}) {
  const findings = [];
  for (const result of json?.results || []) {
    const sourcePath = relativizePath(result?.source?.path || '', repoRoot);
    for (const pkg of result?.packages || []) {
      const name = pkg?.package?.name || 'unknown';
      const version = pkg?.package?.version || '';
      const ecosystem = pkg?.package?.ecosystem || '';
      const groups = pkg?.groups || [];

      for (const vuln of pkg?.vulnerabilities || []) {
        if (!vuln?.id) continue;
        const group = groups.find((g) => (g?.ids || []).includes(vuln.id));
        const malware = isMalwareAdvisory(vuln);
        // Malware is a different KIND of problem than a vulnerable version — the
        // package itself is hostile, so it's always CRITICAL regardless of CVSS.
        const severity = malware
          ? 'CRITICAL'
          : cvssScoreToSeverity(group?.max_severity) !== 'UNKNOWN'
            ? cvssScoreToSeverity(group?.max_severity)
            : normalizeSeverityWord(vuln?.database_specific?.severity);

        const cveId =
          (vuln.id.startsWith('CVE-') && vuln.id) ||
          (vuln.aliases || []).find((a) => typeof a === 'string' && a.startsWith('CVE-')) ||
          null;
        const fixedVersion = extractFixedVersion(vuln, { name, ecosystem, version });

        const finding = {
          type: malware ? FINDING_TYPES.MALWARE : FINDING_TYPES.SCA,
          ruleId: vuln.id, // OSV id (MAL-…, GHSA-…, GO-…, or CVE-…)
          ruleName: clip(vuln.summary || vuln.id, 300),
          severity,
          file: sourcePath || null,
          line: null,
          column: null,
          description: clip(vuln.summary || vuln.details || vuln.id),
          // Malware isn't "upgrade to a fixed version" — there is no safe version;
          // the package must be removed/replaced.
          remediation: malware
            ? `Remove ${name} (${ecosystem || 'unknown ecosystem'}) immediately — this package is flagged malicious by OSV (${vuln.id}). Do not upgrade; replace it and rotate any secrets it could have accessed.`
            : fixedVersion
              ? `Upgrade ${name} to ${fixedVersion} or later (${ecosystem || 'unknown ecosystem'}).`
              : null,
          cveId,
          packageName: name,
          packageEcosystem: ecosystem || null,
          packageVersion: version || null,
          fixedVersion,
          cwe: null,
          evidence: {
            engine: 'osv-scanner',
            osvId: vuln.id,
            aliases: vuln.aliases || [],
            lockfile: sourcePath || null,
            modified: vuln.modified || null,
            // WHERE in the package the vulnerability lives, when the advisory says so. This is the
            // only authoritative vulnerable-symbol source we get for free — GoVulnDB populates it
            // and osv-scanner passes it through verbatim (verified: 34 of the advisories on one Go
            // module carried it). Without it, "is this dependency reachable?" can only ever be
            // answered at package granularity. Schema: https://ossf.github.io/osv-schema/#go
            ...vulnerableLocations(vuln, { name, ecosystem }),
          },
        };
        finding.identityKey = buildIdentityKey(finding);
        findings.push(finding);
      }
    }
  }
  return findings;
}

/**
 * The fixed version for the matching (ecosystem, package), CHOSEN FOR THE INSTALLED VERSION's branch.
 *
 * Multi-branch advisories list a fix per major line — e.g. @babel/core GHSA-4x5r-pxfx-6jf8 is fixed in
 * BOTH 7.29.6 (v7) and 8.0.0-rc.6 (v8). Returning the first `event.fixed` across all ranges pointed a
 * 7.29.0 install at the 8.0.0 MAJOR bump (breaking + a pre-release) instead of its own 7.29.6 patch —
 * which then mis-routed AVR to a backport. So: collect every fixed version, then prefer the one on the
 * SAME major as the installed version (the nearest in-major upgrade); else the lowest fix on a major
 * ≥ the installed major (nearest forward branch); else the first fix.
 */
/**
 * The advisory's own statement of WHERE the vulnerability lives: import paths + symbols.
 *
 * Scoped to the `affected` entry for THIS package — a multi-package advisory lists paths for every
 * affected module, and mixing them in would claim a path belongs to a package it does not.
 * GO-2026-5004 is the live example: it lists internal/sanitize under pgx v4 AND v5.
 *
 * Returns `{}` when the advisory says nothing, so the evidence blob stays clean and a consumer can
 * tell "the advisory did not localize this" from "it localized it to nothing".
 */
function vulnerableLocations(vuln, { name, ecosystem }) {
  const paths = new Set();
  const symbols = new Set();
  for (const affected of vuln?.affected || []) {
    const pkg = affected?.package || {};
    if (pkg.name && pkg.name !== name) continue;
    if (pkg.ecosystem && ecosystem && pkg.ecosystem !== ecosystem) continue;
    for (const imp of affected?.ecosystem_specific?.imports || []) {
      if (imp?.path) paths.add(imp.path);
      for (const s of imp?.symbols || []) if (s) symbols.add(s);
    }
  }
  if (!paths.size && !symbols.size) return {};
  return {
    ...(paths.size ? { vulnerablePaths: [...paths].sort() } : {}),
    ...(symbols.size ? { vulnerableSymbols: [...symbols].sort() } : {}),
  };
}

/**
 * OSV range types whose `fixed` events name a VERSION. Per the OSV schema, `affected[].ranges[].type`
 * is one of GIT | SEMVER | ECOSYSTEM, and in a GIT range the events are **commit hashes**, not
 * versions: https://ossf.github.io/osv-schema/#affectedranges-field
 *
 * THE BUG THIS CLOSES (observed on prod 2026-08-08). This loop had no type filter, so commit hashes
 * were collected as candidate fixed versions. `PYSEC-2023-74` (requests, CVE-2023-32681) carries BOTH
 * a GIT range fixed at `74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5` and the real ECOSYSTEM fix at
 * `2.31.0`; seven prod AppSecFinding rows ended up with that hash as their `fixedVersion`, and one
 * reached AvrRemediation as an `officialFixedVersion` — which is the field that decides
 * upgrade-vs-backport, so `majorOf('74ea7cf7…')` = 74 read as "crosses a major" and manufactured a
 * backport request for a CVE whose honest fix is `pip install requests==2.31.0`.
 *
 * The same-major preference below masks this MOST of the time, which is why it survived: for an
 * installed 2.26.0 the real 2.31.0 wins on major 2. It does not always mask it — a hash beginning
 * with the installed major's digit (`2ab34c…` against a 2.x package) matches `sameMajor` FIRST and is
 * returned as the fix. Filtering by range type removes the class instead of relying on that luck.
 */
const VERSION_RANGE_TYPES = new Set(['SEMVER', 'ECOSYSTEM']);
/** A bare 7+ hex-digit token is a commit id, never a version — belt to the type filter's braces. */
const looksLikeCommitSha = (v) => /^[0-9a-f]{7,40}$/i.test(String(v || '')) && /[a-f]/i.test(String(v || ''));

function extractFixedVersion(vuln, { name, ecosystem, version }) {
  const fixes = [];
  for (const affected of vuln?.affected || []) {
    const pkg = affected?.package || {};
    if (pkg.name !== name) continue;
    if (ecosystem && pkg.ecosystem && pkg.ecosystem !== ecosystem) continue;
    for (const range of affected?.ranges || []) {
      // An absent type is not assumed to be a version range — OSV marks `type` required, so a record
      // without one is malformed and we would rather skip it than guess.
      if (!VERSION_RANGE_TYPES.has(String(range?.type || '').toUpperCase())) continue;
      for (const event of range?.events || []) {
        if (event?.fixed && !looksLikeCommitSha(event.fixed)) fixes.push(event.fixed);
      }
    }
  }
  if (!fixes.length) return null;
  const majorOf = (v) => parseInt(String(v || '').replace(/^[^\d]*/, '').split('.')[0], 10);
  const vMaj = version != null ? majorOf(version) : NaN;
  if (!Number.isNaN(vMaj)) {
    const sameMajor = fixes.find((f) => majorOf(f) === vMaj);
    if (sameMajor) return sameMajor;
    const forward = fixes.filter((f) => majorOf(f) >= vMaj).sort((a, b) => majorOf(a) - majorOf(b))[0];
    if (forward) return forward;
  }
  return fixes[0];
}

/**
 * Normalize `gitleaks git --report-format json` output (8.x): an array of
 * leak objects. Every confirmed leak is CRITICAL — a credential committed to
 * git history is compromised even if the commit was later reverted; rotation
 * is the only fix.
 *
 * Data minimization: Secret/Match/Author/Email are dropped. Commit sha +
 * date + rule metadata are enough for an analyst to locate and rotate.
 */
export function normalizeGitleaksResults(json, { repoRoot = '' } = {}) {
  const leaks = Array.isArray(json) ? json : [];
  const findings = [];
  for (const leak of leaks) {
    if (!leak || !leak.RuleID) continue;
    const file = relativizePath(leak.File || '', repoRoot) || null;
    const commit = leak.Commit || '';
    const finding = {
      type: FINDING_TYPES.SECRET,
      ruleId: leak.RuleID,
      ruleName: clip(leak.Description || leak.RuleID, 300),
      severity: 'CRITICAL',
      file,
      line: Number.isFinite(leak.StartLine) ? leak.StartLine : null,
      column: Number.isFinite(leak.StartColumn) ? leak.StartColumn : null,
      description: clip(
        `${leak.Description || leak.RuleID} detected in ${file || 'repository'}` +
          (commit ? ` (commit ${commit.slice(0, 8)})` : '')
      ),
      remediation:
        'Rotate the credential immediately — committed secrets remain exposed in git ' +
        'history even after removal. Then purge or invalidate the leaked value and add ' +
        'a pre-commit gitleaks hook if missing.',
      cveId: null,
      packageName: null,
      packageEcosystem: null,
      packageVersion: null,
      fixedVersion: null,
      cwe: 'CWE-798', // Use of Hard-coded Credentials
      fingerprint: leak.Fingerprint || null,
      evidence: {
        engine: 'gitleaks',
        rule: leak.RuleID,
        commit: commit || null,
        commitDate: leak.Date || null,
        entropy: Number.isFinite(leak.Entropy) ? leak.Entropy : null,
        tags: leak.Tags || [],
        // Secret / Match / Author / Email intentionally omitted.
      },
    };
    finding.identityKey = buildIdentityKey(finding);
    delete finding.fingerprint; // consumed by buildIdentityKey; not a DB column
    findings.push(finding);
  }
  return findings;
}

// ── SAST (ast-grep) ──────────────────────────────────────────────────────
//
// ast-grep severity is the rule author's choice (error/warning/info/hint). We
// author the rules, so the mapping is deliberate: `error` = a high-confidence
// dangerous sink (eval, unsafe deserialization, disabled TLS verify); `warning`
// = a weaker-signal smell (weak hash, Function ctor). v1 is structural — we flag
// the sink without confirming the input is attacker-controlled — so even an
// `error` rule tops out at HIGH, never CRITICAL (that's reserved for confirmed
// exploitability, a v2 taint concern).
const SEVERITY_BY_ASTGREP = { error: 'HIGH', warning: 'MEDIUM', info: 'LOW', hint: 'LOW' };

// Remediation is keyed by CWE (parsed from the rule message) rather than per
// rule id — the 120+ rules across 9 languages collapse to ~15 vulnerability
// classes, each with one canonical fix. The rule message already carries the
// language-specific "use X instead" detail; this is the class-level guidance.
const SAST_REMEDIATION_BY_CWE = {
  'CWE-78': 'Pass arguments as an argv array to exec/spawn/ProcessBuilder; never interpolate untrusted input into a shell command string.',
  'CWE-79': 'Escape/sanitize untrusted data before rendering as HTML. Prefer textContent or an auto-escaping template; sanitize with a vetted library (e.g. DOMPurify) when raw HTML is required.',
  'CWE-89': 'Use parameterized queries / prepared statements with bound parameters. Never build SQL by string concatenation, formatting, or interpolation.',
  'CWE-90': 'Escape LDAP special characters or use a parameterized LDAP API; never concatenate untrusted input into a filter.',
  'CWE-94': 'Do not pass untrusted input to a code or template evaluator. Use a sandboxed template engine with autoescaping and a fixed template source.',
  'CWE-95': 'Avoid eval/Function/exec on dynamic input. Use a safe parser (JSON.parse / ast.literal_eval) or an explicit allowlist of operations.',
  'CWE-120': 'Use bounded operations with explicit destination sizes (strlcpy/strncpy, snprintf/vsnprintf). Never strcpy/strcat/sprintf/gets.',
  'CWE-134': 'Use a constant format string and pass data as arguments (e.g. printf("%s", data)); never pass untrusted data as the format string.',
  'CWE-242': 'Replace gets() with fgets() using an explicit buffer size — gets() cannot be used safely.',
  'CWE-295': 'Do not disable certificate or hostname verification. Configure the correct CA trust chain instead.',
  'CWE-327': 'Use a modern algorithm: SHA-256+ for hashing, AES-GCM for encryption. Never MD5/SHA-1/DES/3DES/RC4 or ECB mode for security.',
  'CWE-330': 'Use a cryptographically secure RNG (crypto.randomBytes/randomUUID, java.security.SecureRandom, RandomNumberGenerator, getrandom/arc4random) for tokens, keys, and nonces.',
  'CWE-338': 'Use a cryptographically secure RNG (crypto.randomBytes/randomUUID, java.security.SecureRandom, RandomNumberGenerator, getrandom/arc4random) for tokens, keys, and nonces.',
  'CWE-377': 'Create temp files atomically (mkstemp / NamedTemporaryFile); never use mktemp, which is race-condition-prone.',
  'CWE-502': 'Never deserialize untrusted data with a native serializer. Use a data-only format (JSON) with schema validation, or restrict to an allowlist of known types.',
  'CWE-611': 'Disable DTD processing and external-entity resolution on the XML parser (disallow-doctype-decl / DtdProcessing.Prohibit / defusedxml).',
  'CWE-20': 'Keep platform request/input validation enabled and validate every input against an allowlist; encode output at the sink.',
  'CWE-22': 'Resolve the path under a fixed base directory and reject any result that escapes it (realpath / path.resolve + prefix check). For archives, validate each entry path before extracting.',
  'CWE-183': 'Replace wildcard host/origin allowlists with an explicit list of permitted hostnames.',
  'CWE-190': 'Validate and clamp numeric input, and use overflow-checked arithmetic/allocators (calloc, checked multiply) before sizing buffers.',
  'CWE-200': 'Do not expose debug/profiling/management endpoints publicly — bind them to localhost or require auth, and disable them in production.',
  'CWE-252': 'Check the return value of privilege-dropping and other security-relevant calls, and fail closed when they error.',
  'CWE-276': 'Create files and directories with least-privilege modes (e.g. 0600 / 0750); never world-writable 0777 / 0666.',
  'CWE-326': 'Require TLS 1.2+ and RSA keys of at least 2048 bits (prefer ECDSA / Ed25519); disable SSLv3 / TLS 1.0 / TLS 1.1.',
  'CWE-345': 'Pin an explicit target origin on postMessage and verify event.origin in every message handler.',
  'CWE-347': 'Always verify the token signature with a pinned algorithm allowlist; never accept the "none" algorithm or disable verification.',
  'CWE-352': 'Keep CSRF / anti-forgery protection enabled for state-changing requests; use SameSite cookies and per-session tokens.',
  'CWE-470': 'Do not load classes or modules from untrusted input; map user input to a fixed allowlist of permitted types.',
  'CWE-489': 'Disable debug mode in production (DEBUG / debug = False) and gate it behind an environment flag.',
  'CWE-601': 'Redirect only to validated local paths or an allowlist of hosts; never redirect to a raw user-supplied URL.',
  'CWE-614': 'Set Secure, HttpOnly, and SameSite on session and authentication cookies.',
  'CWE-643': 'Use parameterized XPath (variable bindings) or strictly validate input; never concatenate input into an expression.',
  'CWE-668': 'Bind services to a specific interface (127.0.0.1 for local-only) and firewall any public exposure intentionally.',
  'CWE-732': 'Grant least-privilege file permissions; never chmod 0777 / 0666 on files holding sensitive data.',
  'CWE-770': 'Avoid unbounded stack allocation (alloca / VLAs); use a bounded heap allocation with an explicit size cap.',
  'CWE-787': 'Bound every write to the destination buffer size — use length-checked APIs (snprintf, memcpy_s) and validate indices.',
  'CWE-798': 'Load secrets from the environment or a secret manager; never commit credentials or keys to source.',
  'CWE-917': 'Upgrade Log4j to >=2.17, disable message lookups, and never log untrusted data through an interpolating layout.',
  'CWE-918': 'Validate the destination host against an allowlist before making the request, and block internal / metadata IP ranges.',
  'CWE-942': 'Pin explicit allowed origins; never combine a wildcard origin with credentialed requests.',
  'CWE-943': 'Reject query operators from user input; use typed, parameterized queries.',
  'CWE-1022': 'Add rel="noopener noreferrer" to every target="_blank" link.',
  'CWE-1188': 'Disable nodeIntegration and enable contextIsolation in Electron renderers; expose a minimal API through a preload script.',
  'CWE-1333': 'Avoid catastrophic-backtracking patterns and set a regex match timeout, or use a linear-time engine (RE2).',
};

// Canonical "fixed code" examples for the judgment-required injection classes
// — there is no safe mechanical rewrite, so (like every pre-AI SAST tool) we
// show an illustrative secure pattern. AI later upgrades these to a
// context-aware patch; the storage shape (`evidence.fix`) is identical.
const SAST_FIX_EXAMPLE_BY_CWE = {
  'CWE-78': "// Pass args as an array — no shell:\nexecFile('ls', [userInput], cb)",
  'CWE-89': "// Parameterized query (placeholders, not concatenation):\ndb.query('SELECT * FROM users WHERE id = $1', [id])",
  'CWE-90': '// Escape LDAP metacharacters or use a parameterized search filter',
  'CWE-94': '// Render a fixed template; pass user data as context, never as the template source',
  'CWE-95': "// Replace eval with a safe parser or an allow-listed dispatch:\nconst result = JSON.parse(input)",
  'CWE-79': "// Escape/sanitize before rendering:\nel.textContent = userInput   // or DOMPurify.sanitize(html)",
  'CWE-295': "// Keep TLS verification on; trust the correct CA chain:\nhttps.get(url, { rejectUnauthorized: true })",
  'CWE-327': "// Use a modern algorithm — SHA-256 for hashing, AES-GCM for encryption:\ncrypto.createHash('sha256')",
  'CWE-120': '// Bounded copy with an explicit size:\nstrlcpy(dst, src, sizeof(dst))',
  'CWE-134': '// Constant format string; data as args:\nprintf("%s", userInput)',
  'CWE-242': '// gets() has no bound — use fgets:\nfgets(buf, sizeof(buf), stdin)',
  'CWE-502': "// Use a data-only format with schema validation:\nconst obj = JSON.parse(input)",
  'CWE-611': '// Disable DTD + external entities (defusedxml / DtdProcessing.Prohibit / disallow-doctype-decl)',
  'CWE-918': "// Allowlist the host before the request:\nif (!ALLOWED_HOSTS.has(new URL(url).host)) throw new Error('blocked host')",
  'CWE-22': "// Confine under a base directory:\nconst p = path.resolve(BASE, name);\nif (!p.startsWith(BASE + path.sep)) throw new Error('path traversal')",
  'CWE-943': '// Reject query operators from user input; use typed, parameterized filters',
  'CWE-330': '// Use a CSPRNG: java.security.SecureRandom / RandomNumberGenerator',
  'CWE-338': '// Cryptographically secure RNG:\ncrypto.randomUUID()   // or crypto.randomBytes(32)',
  'CWE-20': "// Keep request validation on; validate against an allowlist:\nif (!ALLOWED.test(input)) throw new Error('invalid input')",
  'CWE-183': "// Pin explicit hosts, not a wildcard:\nALLOWED_HOSTS = ['app.example.com']",
  'CWE-190': '// Overflow-safe allocation:\nchar *p = calloc(n, size);   // not malloc(n * size)',
  'CWE-200': '// Do not register debug/profiling endpoints on a public mux; bind internal-only + require auth',
  'CWE-252': '// Check the result and fail closed:\nif (setuid(uid) != 0) { abort(); }',
  'CWE-276': '// Least-privilege mode:\nos.MkdirAll(dir, 0o750)   // not 0o777',
  'CWE-326': '// Require TLS 1.2+ / RSA >= 2048:\n&tls.Config{MinVersion: tls.VersionTLS12}',
  'CWE-345': "// Pin the target origin (and verify event.origin on receipt):\nwin.postMessage(msg, 'https://app.example.com')   // not '*'",
  'CWE-347': "// Verify with a pinned algorithm; never alg 'none':\njwt.verify(token, key, { algorithms: ['RS256'] })",
  'CWE-352': '// Keep CSRF protection on; require a per-session anti-forgery token on state-changing requests',
  'CWE-377': '// Atomic temp file:\nint fd = mkstemp(template);   // never tmpnam/tempnam/mktemp',
  'CWE-470': '// Map input to an allowlisted handler — never Class.forName(userInput) / require(userInput)',
  'CWE-489': "// Drive debug from the environment, never hardcoded:\nDEBUG = os.environ.get('DEBUG') == '1'",
  'CWE-601': "// Allowlist redirect targets:\nif (!ALLOWED_PATHS.has(target)) target = '/'",
  'CWE-614': "// Harden the cookie:\nres.cookie('sid', v, { secure: true, httpOnly: true, sameSite: 'lax' })",
  'CWE-643': '// Bind variables instead of concatenating into the XPath expression',
  'CWE-668': "// Bind to a specific interface:\napp.run(host='127.0.0.1')   // not 0.0.0.0 unless intended",
  'CWE-732': '// Least-privilege file mode:\nos.chmod(path, 0o600)   // not 0o777',
  'CWE-770': '// Bounded heap allocation instead of alloca(n):\nchar *buf = malloc(n < MAX ? n : MAX)',
  'CWE-787': '// Bounded write:\nsnprintf(dst, sizeof(dst), "%s", src)',
  'CWE-798': '// Load from the environment / a secret manager:\nconst secret = process.env.JWT_SECRET',
  'CWE-917': '// Upgrade Log4j >= 2.17, disable lookups; never interpolate ${...} from user input',
  'CWE-942': "// Pin explicit origins; do not pair '*' with credentials:\ncors({ origin: ['https://app.example.com'], credentials: true })",
  'CWE-1022': '// Add rel to target=_blank:\n<a href={url} target="_blank" rel="noopener noreferrer">',
  'CWE-1188': '// Lock down the renderer:\nnew BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } })',
  'CWE-1333': '// Bound match time / use a linear-time engine:\nnew Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1))',
};

// Language-specific secure-pattern examples — preferred over the generic
// SAST_FIX_EXAMPLE_BY_CWE above when a finding's language is known, so a Python
// finding gets Python code and a Go finding gets Go code (not a generic JS
// snippet). Falls back to the generic map for any (language, CWE) pair not
// listed here, so coverage never regresses. Enterprise AI-autofix (#989) later
// upgrades these to a context-aware patch of the user's actual line.
const _JS_FIX = {
  'CWE-22': "// Confine under a base dir, reject escapes:\nconst p = path.resolve(BASE, name);\nif (!p.startsWith(BASE + path.sep)) throw new Error('path traversal');",
  'CWE-78': "// No shell — pass args as an argv array:\nexecFile('ls', ['-la', userInput], cb);",
  'CWE-79': "// Render as text, or sanitize raw HTML:\nel.textContent = userInput;   // or: el.innerHTML = DOMPurify.sanitize(html)",
  'CWE-89': "// Parameterized query — placeholders, never concat:\ndb.query('SELECT * FROM users WHERE id = $1', [id]);",
  'CWE-94': "// Don't evaluate input; parse it:\nconst data = JSON.parse(input);",
  'CWE-95': "// Replace eval/Function with a safe parser or allow-listed dispatch:\nconst result = JSON.parse(input);",
  'CWE-295': "// Keep TLS verification on; trust the real CA chain:\nhttps.get(url, { rejectUnauthorized: true });",
  'CWE-327': "// SHA-256 for hashing, AES-256-GCM for encryption:\ncrypto.createHash('sha256');\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);",
  'CWE-338': "// Cryptographically secure RNG for tokens/keys/IVs:\nconst token = crypto.randomUUID();   // or crypto.randomBytes(32)",
  'CWE-345': "// Pin the target origin (and verify event.origin on receipt):\nwin.postMessage(msg, 'https://app.example.com');   // not '*'",
  'CWE-347': "// Verify with a pinned algorithm; never 'none':\njwt.verify(token, key, { algorithms: ['RS256'] });",
  'CWE-502': "// Use a data-only format with schema validation:\nconst obj = JSON.parse(input);   // never node-serialize unserialize()",
  'CWE-601': "// Allowlist redirect targets:\nif (!ALLOWED_PATHS.has(target)) target = '/';\nres.redirect(target);",
  'CWE-614': "// Harden the cookie:\nres.cookie('sid', v, { httpOnly: true, secure: true, sameSite: 'lax' });",
  'CWE-798': "// Load from env / a secret manager, never hardcode:\nconst secret = process.env.JWT_SECRET;\njwt.sign(payload, secret);",
  'CWE-918': "// Allowlist the host before the request:\nif (!ALLOWED_HOSTS.has(new URL(url).host)) throw new Error('blocked host');\nawait fetch(url);",
  'CWE-942': "// Pin explicit origins; never '*' with credentials:\ncors({ origin: ['https://app.example.com'], credentials: true });",
  'CWE-943': "// Reject query operators from input; coerce to a typed value:\ndb.find({ user: String(input) });   // never { $where: input }",
  'CWE-1188': "// Lock down the Electron renderer:\nnew BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });",
};
const _C_FIX = {
  'CWE-78': "// Absolute path + argv array — no PATH search, no shell:\nchar *const argv[] = {\"/bin/ls\", arg, NULL};\nexecv(\"/bin/ls\", argv);",
  'CWE-120': "// Bounded copy with explicit destination size:\nstrlcpy(dst, src, sizeof(dst));\nsnprintf(dst, sizeof(dst), \"%s\", src);",
  'CWE-134': "// Constant format string; data as args:\nprintf(\"%s\", userInput);   // never printf(userInput)",
  'CWE-190': "// Overflow-safe allocation; checked integer parse:\nchar *p = calloc(n, size);   // not malloc(n * size)",
  'CWE-242': "// gets() has no bound — use fgets with a size:\nfgets(buf, sizeof(buf), stdin);",
  'CWE-252': "// Check the privilege-drop result and fail closed:\nif (setuid(uid) != 0) { perror(\"setuid\"); abort(); }",
  'CWE-295': "// Keep TLS verification ON; trust the correct CA chain:\ncurl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);\ncurl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);",
  'CWE-327': "// Use a modern algorithm — SHA-256+, never MD5/SHA-1:\nSHA256(data, len, out);",
  'CWE-330': "// Reentrant, thread-safe tokenizer:\nchar *save;\nchar *tok = strtok_r(buf, \",\", &save);",
  'CWE-338': "// Cryptographically secure RNG — not rand()/srand(time()):\nuint32_t r = arc4random();\ngetrandom(key, sizeof(key), 0);",
  'CWE-377': "// Atomic temp file — never tmpnam/tempnam/mktemp:\nchar tmpl[] = \"/tmp/app-XXXXXX\";\nint fd = mkstemp(tmpl);",
  'CWE-732': "// Least-privilege mode (owner only):\nchmod(path, 0600);   // not 0777 / 0666",
  'CWE-770': "// Bounded heap allocation instead of alloca(n):\nif (n > MAX) n = MAX;\nchar *buf = malloc(n);   if (!buf) return -1;",
  'CWE-787': "// Bound every write to the destination size:\nsnprintf(dst, sizeof(dst), \"%s\", src);",
};
const SAST_FIX_EXAMPLE_BY_LANG_CWE = {
  python: {
    'CWE-22': "# Confine under a base dir:\np = os.path.realpath(os.path.join(BASE, name))\nif not (p + os.sep).startswith(BASE + os.sep): raise ValueError('path traversal')",
    'CWE-78': "# Pass argv as a list, no shell:\nsubprocess.run(['ls', '-l', user_dir], shell=False, check=True)",
    'CWE-79': "# Let the template auto-escape; never mark_safe untrusted data:\nreturn render(request, 'p.html', {'name': name})  # not mark_safe(name)",
    'CWE-89': "# Parameterized query (placeholders, not %/format/concat):\ncur.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    'CWE-94': "# Render a fixed template; pass user data as context, never as the source:\nreturn render_template('page.html', name=name)",
    'CWE-95': "# Replace eval/exec with a safe parser:\nimport ast\nvalue = ast.literal_eval(user_input)",
    'CWE-183': "# Pin explicit hosts, not a wildcard:\nALLOWED_HOSTS = ['app.example.com']",
    'CWE-295': "# Keep TLS verification on; trust the correct CA chain:\nrequests.get(url, verify=True)  # default ssl.create_default_context()",
    'CWE-327': "# Use a modern algorithm — SHA-256+ for hashing, AES-GCM for ciphers:\nh = hashlib.sha256(data).hexdigest()",
    'CWE-347': "# Verify the signature with a pinned algorithm allowlist:\njwt.decode(token, key, algorithms=['RS256'])  # never 'none'/verify_signature=False",
    'CWE-352': "# Keep CSRF protection on — remove @csrf_exempt; use the {% csrf_token %} / per-session token",
    'CWE-377': "# Atomic temp file (no TOCTOU):\nfd, path = tempfile.mkstemp()  # or tempfile.NamedTemporaryFile()",
    'CWE-489': "# Drive debug from the environment, never hardcoded:\nDEBUG = os.environ.get('DEBUG') == '1'",
    'CWE-502': "# Use a data-only loader (no arbitrary objects):\nobj = yaml.safe_load(text)  # or json.loads(text)",
    'CWE-611': "# Disable external entities — use defusedxml:\nfrom defusedxml.ElementTree import parse\ntree = parse(src)  # or lxml XMLParser(resolve_entities=False)",
    'CWE-614': "# Harden the session/CSRF cookie:\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nCSRF_COOKIE_SECURE = True",
    'CWE-668': "# Bind to a specific interface, not all of them:\napp.run(host='127.0.0.1')  # not '0.0.0.0' unless intended",
    'CWE-732': "# Least-privilege file mode:\nos.chmod(path, 0o600)  # not 0o777 / 0o666",
    'CWE-798': "# Load secrets from the environment / a secret manager:\nSECRET_KEY = os.environ['SECRET_KEY']",
    'CWE-918': "# Allowlist the host before the request:\nif urlparse(url).hostname not in ALLOWED_HOSTS: raise ValueError('blocked host')\nrequests.get(url)",
  },
  go: {
    'CWE-22': "// Clean + confine under a base dir:\np := filepath.Join(base, name)\nif !strings.HasPrefix(p, filepath.Clean(base)+string(os.PathSeparator)) { return errors.New(\"path traversal\") }",
    'CWE-78': "// Pass argv directly — no shell:\ncmd := exec.Command(\"ls\", \"-l\", userDir)  // not sh -c <string>",
    'CWE-79': "// Let html/template auto-escape; never cast untrusted data:\nt.Execute(w, userInput)  // not template.HTML(userInput)",
    'CWE-89': "// Parameterized query with placeholders:\nrow := db.QueryRow(\"SELECT * FROM users WHERE id = $1\", id)",
    'CWE-200': "// Don't expose pprof on a public mux — register it on an internal, auth'd server, or omit in prod",
    'CWE-276': "// Least-privilege mode:\nos.MkdirAll(dir, 0o750)  // not 0777",
    'CWE-295': "// Keep host-key/cert verification on:\nhostKeyCallback, _ := knownhosts.New(\"known_hosts\")  // not ssh.InsecureIgnoreHostKey()",
    'CWE-326': "// Require TLS 1.2+ / RSA >= 2048:\ncfg := &tls.Config{MinVersion: tls.VersionTLS12}",
    'CWE-327': "// Use a modern algorithm — sha256 for hashing, AES-GCM for ciphers:\nsum := sha256.Sum256(data)",
    'CWE-347': "// Verify with a pinned signing method; never 'none':\ntok, err := jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{\"RS256\"}))",
    'CWE-668': "// Bind to a specific interface, not all of them:\nln, _ := net.Listen(\"tcp\", \"127.0.0.1:8080\")  // not 0.0.0.0",
    'CWE-918': "// Allowlist the host before the request:\nif !allowedHosts[u.Hostname()] { return errors.New(\"blocked host\") }\nresp, err := http.Get(rawURL)",
  },
  java: {
    'CWE-22': "// Confine under a base directory:\nPath base = Paths.get(\"/srv/data\").toRealPath();\nPath p = base.resolve(name).normalize();\nif (!p.startsWith(base)) throw new IOException(\"path traversal\");",
    'CWE-78': "// Argv list, no shell — never a built string:\nProcessBuilder pb = new ProcessBuilder(\"ls\", \"-l\", userInput);\npb.start();",
    'CWE-89': "// Parameterized query:\nPreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setInt(1, id);\nResultSet rs = ps.executeQuery();",
    'CWE-90': "// Escape LDAP metacharacters / use a parameterized filter:\nString filter = \"(uid={0})\";\nctx.search(base, filter, new Object[]{ userInput }, controls);",
    'CWE-94': "// Don't eval untrusted input — map to an allow-listed operation:\nRunnable op = ALLOWED_OPS.get(name);\nif (op == null) throw new IllegalArgumentException(\"unknown op\");\nop.run();",
    'CWE-295': "// Keep TLS hostname + cert verification on — trust the correct CA chain:\nHttpsURLConnection c = (HttpsURLConnection) url.openConnection();\nc.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());",
    'CWE-327': "// Modern algorithm — SHA-256 for hashing, AES-GCM for encryption:\nMessageDigest md = MessageDigest.getInstance(\"SHA-256\");\nCipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");",
    'CWE-330': "// Cryptographically secure RNG — let it self-seed:\nSecureRandom rng = new SecureRandom();\nbyte[] token = new byte[32];\nrng.nextBytes(token);",
    'CWE-352': "// Keep Spring Security CSRF protection enabled:\nhttp.csrf(Customizer.withDefaults());",
    'CWE-470': "// Map input to an allow-listed type — never Class.forName(userInput):\nClass<?> c = ALLOWED_TYPES.get(name);\nif (c == null) throw new IllegalArgumentException(\"type not allowed\");",
    'CWE-502': "// Use a data-only format with schema validation, not native deserialization:\nObjectMapper om = new ObjectMapper();\nMyDto dto = om.readValue(json, MyDto.class);",
    'CWE-601': "// Allow-list redirect targets:\nMap<String,String> ALLOWED = Map.of(\"home\", \"/home\");\nString dest = ALLOWED.getOrDefault(target, \"/\");\nresponse.sendRedirect(dest);",
    'CWE-611': "// Disable DTDs / external entities:\nDocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\nf.setExpandEntityReferences(false);",
    'CWE-614': "// Harden session cookies:\nCookie c = new Cookie(\"sid\", value);\nc.setSecure(true);\nc.setHttpOnly(true);",
    'CWE-917': "// Upgrade Log4j >= 2.17; never log untrusted data through an interpolating layout:\nlog.info(\"user={}\", sanitize(userInput));",
    'CWE-918': "// Allow-list the host before opening the connection:\nString host = new URI(target).getHost();\nif (!ALLOWED_HOSTS.contains(host)) throw new IOException(\"blocked host\");\nnew URL(target).openConnection();",
    'CWE-942': "// Pin explicit origins, never a wildcard:\nconfig.setAllowedOrigins(List.of(\"https://app.example.com\"));",
  },
  csharp: {
    'CWE-20': "// Keep ASP.NET request validation on; validate input against an allowlist:\nif (!Regex.IsMatch(input, \"^[a-zA-Z0-9_-]+$\")) return BadRequest();\n// do not use [ValidateInput(false)]",
    'CWE-22': "// Confine under a base directory:\nvar baseDir = Path.GetFullPath(\"C:\\\\srv\\\\data\");\nvar full = Path.GetFullPath(Path.Combine(baseDir, name));\nif (!full.StartsWith(baseDir)) throw new UnauthorizedAccessException();",
    'CWE-78': "// Pass args separately and validate against an allowlist — no shell string:\nvar psi = new ProcessStartInfo(\"ls\") { UseShellExecute = false };\npsi.ArgumentList.Add(userInput);\nProcess.Start(psi);",
    'CWE-79': "// Encode untrusted values — avoid Html.Raw:\n@Html.Encode(model.Comment)   // or @model.Comment (auto-encoded)",
    'CWE-89': "// Parameterized command:\nusing var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = @id\", conn);\ncmd.Parameters.Add(new SqlParameter(\"@id\", id));\n// EF Core: db.Users.FromSqlInterpolated($\"... WHERE Id = {id}\")",
    'CWE-90': "// Escape LDAP metacharacters before building the filter:\nvar safe = LdapEncoder.FilterEncode(userInput);\nvar searcher = new DirectorySearcher($\"(uid={safe})\");",
    'CWE-94': "// Disable script + document() in XSLT:\nvar settings = new XsltSettings(enableDocumentFunction: false, enableScript: false);\nxslt.Load(stylesheet, settings, new XmlUrlResolver());",
    'CWE-295': "// Do not bypass cert validation — leave the default callback in place:\nvar handler = new HttpClientHandler();   // validates by default",
    'CWE-326': "// Require TLS 1.2+ and RSA >= 2048 (prefer ECDSA):\nvar opts = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 };\nusing var rsa = RSA.Create(2048);",
    'CWE-327': "// Modern algorithm — SHA256 for hashing, AES for encryption:\nusing var sha = SHA256.Create();\nusing var aes = Aes.Create();   // AES-GCM/CBC, not DES/3DES/ECB",
    'CWE-338': "// Cryptographically secure RNG for tokens/keys/nonces:\nvar token = new byte[32];\nRandomNumberGenerator.Fill(token);",
    'CWE-352': "// Keep anti-forgery on for state-changing actions:\n[HttpPost]\n[ValidateAntiForgeryToken]\npublic IActionResult Update(Model m) { }",
    'CWE-502': "// Use a safe serializer with known types — not BinaryFormatter / TypeNameHandling:\nvar dto = JsonSerializer.Deserialize<MyDto>(json);\n// Json.NET: new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None }",
    'CWE-601': "// Allow-list redirect targets (local paths only):\nif (!Url.IsLocalUrl(returnUrl)) returnUrl = \"/\";\nreturn Redirect(returnUrl);",
    'CWE-611': "// Prohibit DTDs + null the resolver:\nvar settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };\nusing var reader = XmlReader.Create(stream, settings);",
    'CWE-614': "// Harden session cookies:\nResponse.Cookies.Append(\"sid\", value, new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Lax });",
    'CWE-643': "// Parameterize XPath with variable bindings — never concatenate input:\nvar nav = doc.CreateNavigator();\nvar expr = nav.Compile(\"/users/user[@id=$id]\");",
    'CWE-918': "// Allow-list the host before the request:\nvar host = new Uri(target).Host;\nif (!AllowedHosts.Contains(host)) throw new InvalidOperationException(\"blocked host\");\nawait httpClient.GetAsync(target);",
    'CWE-942': "// Pin explicit origins, never AllowAnyOrigin/\"*\":\npolicy.WithOrigins(\"https://app.example.com\").AllowCredentials();",
    'CWE-1333': "// Bound regex match time against ReDoS:\nvar re = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));",
  },
  javascript: _JS_FIX,
  typescript: _JS_FIX,
  tsx: { ..._JS_FIX, 'CWE-1022': "// Reverse-tabnabbing guard on target=_blank:\n<a href={url} target=\"_blank\" rel=\"noopener noreferrer\">" },
  c: _C_FIX,
  cpp: _C_FIX,
};

// Derive the rule language from the finding's file extension so we can pick the
// language-specific fix example. .h defaults to C (the c/cpp examples align).
const _EXT_TO_LANG = {
  py: 'python', go: 'go', java: 'java', cs: 'csharp',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'tsx',
  c: 'c', h: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', hxx: 'cpp',
};
function langFromFile(file) {
  const ext = String(file || '').toLowerCase().split('.').pop();
  return _EXT_TO_LANG[ext] || null;
}

/** True when a LANGUAGE-IDIOMATIC fix example exists for (language, cwe) — used
 *  by the discipline test so a new rule can't ship a CWE without a per-language
 *  fix (it would otherwise silently fall back to the generic class example). */
export function hasLanguageSpecificFix(language, cwe) {
  const byLang = SAST_FIX_EXAMPLE_BY_LANG_CWE[language];
  return Boolean(byLang && byLang[cwe]);
}

/**
 * Produce a suggested fix for a SAST finding.
 *  - AUTOFIX: a deterministic mechanical rewrite of the matched snippet (weak
 *    crypto → SHA-256, disabled TLS verify → enabled, mktemp → mkstemp). The
 *    `code` is a true before→after replacement of `matched`.
 *  - EXAMPLE: a canonical secure pattern for injection classes with no safe
 *    mechanical rewrite.
 * Returns null when neither applies. `matched` is the exact matched substring.
 */
export function suggestSastFix(cwe, matched, language) {
  const src = typeof matched === 'string' ? matched : '';
  let fixed = src;

  if (cwe === 'CWE-327') {
    fixed = src
      // Java first: it needs the exact algorithm name "SHA-256" — the generic
      // quoted-literal rule below would otherwise produce invalid "sha256".
      .replace(/getInstance\((['"])(MD5|SHA-1)\1\)/i, 'getInstance($1SHA-256$1)') // java
      .replace(/(['"])(md5|sha-?1)\1/i, '$1sha256$1')                 // js createHash('md5') → 'sha256'
      .replace(/\bmd5\.(New|Sum)\b/, 'sha256.$1')                    // go md5.New → sha256.New
      .replace(/\bsha1\.(New|Sum)\b/, 'sha256.$1')
      .replace(/\b(MD5|SHA1)\.Create\(\)/, 'SHA256.Create()')         // c#
      .replace(/hashlib\.(md5|sha1)\b/, 'hashlib.sha256');           // python
  } else if (cwe === 'CWE-295') {
    fixed = src
      .replace(/rejectUnauthorized:\s*false/, 'rejectUnauthorized: true')
      .replace(/InsecureSkipVerify:\s*true/, 'InsecureSkipVerify: false')
      .replace(/verify\s*=\s*False/, 'verify=True')
      .replace(/(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"])0(['"])/, '$11$2');
  } else if (cwe === 'CWE-377') {
    fixed = src.replace('tempfile.mktemp', 'tempfile.mkstemp');
  }

  if (fixed !== src) return { kind: 'AUTOFIX', original: src, code: fixed };
  // Prefer a language-idiomatic example; fall back to the generic class example.
  const example =
    (language && SAST_FIX_EXAMPLE_BY_LANG_CWE[language] && SAST_FIX_EXAMPLE_BY_LANG_CWE[language][cwe]) ||
    SAST_FIX_EXAMPLE_BY_CWE[cwe];
  if (example) return { kind: 'EXAMPLE', code: example };
  return null;
}

/**
 * Normalize `ast-grep scan --json=compact` output: a flat JSON array of match
 * objects. Each match carries `ruleId`, `severity`, `message`, `file`, `lines`
 * (the matched source line), `text` (the matched substring) and a `range` whose
 * start/end line/column are 0-indexed (we +1 for human display).
 *
 * The matched line(s) are stored as evidence — unlike a leaked secret, source
 * structure is the context an analyst needs. `endLine` + `fix` support the UI's
 * code-context window and before→after suggestion.
 */
export function normalizeAstGrepResults(json, { repoRoot = '' } = {}) {
  const matches = Array.isArray(json) ? json : [];
  const findings = [];
  for (const m of matches) {
    if (!m || !m.ruleId) continue;
    const ruleId = m.ruleId;
    const message = m.message || ruleId;
    const cwe = (message.match(/CWE-\d+/) || [])[0] || null;
    const startLine = m.range?.start?.line;
    const startCol = m.range?.start?.column;
    const endLineRaw = m.range?.end?.line;
    const line = Number.isInteger(startLine) ? startLine + 1 : null;
    const endLine = Number.isInteger(endLineRaw) ? endLineRaw + 1 : line;
    const finding = {
      type: FINDING_TYPES.SAST,
      ruleId,
      ruleName: clip(message, 300),
      severity: SEVERITY_BY_ASTGREP[m.severity] || 'UNKNOWN',
      file: relativizePath(m.file || '', repoRoot) || null,
      line,
      column: Number.isInteger(startCol) ? startCol + 1 : null,
      description: clip(message),
      remediation:
        SAST_REMEDIATION_BY_CWE[cwe] ||
        'Refactor the flagged construct to remove the insecure pattern.',
      cveId: null,
      packageName: null,
      packageEcosystem: null,
      packageVersion: null,
      fixedVersion: null,
      cwe,
      evidence: {
        engine: 'ast-grep',
        rule: ruleId,
        snippet: clip(m.lines || '', 300),
        // Match span end line — consumed by the code-context window builder so a
        // multi-line match highlights fully. Stripped of the leading `_` it is a
        // plain evidence key; the builder reads it then leaves it in place.
        endLine,
        // Suggested fix: deterministic before→after for weak-API/config rules,
        // a canonical secure example for the injection classes. matched text is
        // the exact substring ast-grep flagged.
        fix: suggestSastFix(cwe, m.text, langFromFile(m.file)),
      },
    };
    finding.identityKey = buildIdentityKey(finding);
    findings.push(finding);
  }
  return findings;
}

// ── IaC suggested-fix (trivy config + bicep) ─────────────────────────────────
// Trivy's `Resolution` is captured as the finding's remediation TEXT, but the UI
// also has a dedicated "Suggested Fix" code block (evidence.fix) that — until
// now — only SAST populated. IaC findings showed the offending config + guidance
// text but no corrected CODE. This curated map gives the common cloud misconfigs
// (Azure-weighted: storage / network / Key Vault / identity — the Azure
// customer's surface — plus high-frequency AWS / Dockerfile / K8s rules) an
// illustrative corrected snippet, keyed on Trivy's stable rule IDs (AVD-* /
// AZU-* / DS-* / the AVD aliases). EXAMPLE-kind, same storage shape as SAST, so
// the existing UI renderer shows it unchanged. Snippets are Bicep/HCL-flavored
// illustrations (kind=EXAMPLE = "secure pattern", not a literal patch); the
// long tail falls back to the Resolution text already in `remediation`.
const IAC_FIX_BY_RULE = {
  // Azure Storage
  'AVD-AZU-0008': "// Enforce HTTPS-only transport:\nsupportsHttpsTrafficOnly: true",
  'AVD-AZU-0011': "// Require TLS 1.2 as the floor:\nminimumTlsVersion: 'TLS1_2'",
  'AVD-AZU-0012': "// Default-deny network access, allow-list explicitly:\nnetworkAcls: { defaultAction: 'Deny' }",
  'AVD-AZU-0007': "// Disable anonymous blob/container public access:\nallowBlobPublicAccess: false",
  'AVD-AZU-0010': "// Turn on blob soft-delete retention:\ndeleteRetentionPolicy: { enabled: true, days: 7 }",
  'AVD-AZU-0056': "// Enable blob soft-delete so deletes are recoverable:\nblobServices: { deleteRetentionPolicy: { enabled: true, days: 7 } }",
  'AVD-AZU-0057': "// Enable diagnostic logging (read/write/delete) on the account:\n// configure a Microsoft.Insights/diagnosticSettings resource for the storage account",
  'AVD-AZU-0058': "// Use geo-redundant replication for durability:\nsku: { name: 'Standard_GRS' }",
  'AVD-AZU-0061': "// Enable infrastructure (double) encryption at rest:\nencryption: { requireInfrastructureEncryption: true }",
  // Azure Key Vault
  'AVD-AZU-0013': "// Enable Key Vault soft-delete + purge protection:\nproperties: { enableSoftDelete: true, enablePurgeProtection: true }",
  'AVD-AZU-0016': "// Set an expiry on every key/secret:\nattributes: { exp: <unix-timestamp> }",
  'AVD-AZU-0017': "// Default-deny Key Vault network access:\nnetworkAcls: { defaultAction: 'Deny', bypass: 'AzureServices' }",
  // Azure compute / identity / SQL
  'AVD-AZU-0039': "// Use a customer-managed key for disk encryption:\nencryption: { type: 'EncryptionAtRestWithCustomerKey' }",
  'AVD-AZU-0038': "// Enable system-assigned managed identity instead of static creds:\nidentity: { type: 'SystemAssigned' }",
  // AWS is covered by the generated corpus (IAC_FIX_GENERATED) — richer, authoritative.
  // Dockerfile (DS) — locally verified: a bad Dockerfile fires DS-0001/0002/0013/0017/0026,
  // the fixed one below clears all five (trivy config).
  'AVD-DS-0001': "# Pin a specific version, not :latest:\nFROM node:25.1.0",
  'AVD-DS-0002': "# Run as a non-root user:\nRUN adduser --disabled-password --uid 10001 app\nUSER app",
  'AVD-DS-0013': "# Use WORKDIR instead of 'RUN cd':\nWORKDIR /app",
  'AVD-DS-0017': "# Combine update+install in one layer so the apt cache can't go stale:\nRUN apt-get update && apt-get install -y --no-install-recommends <pkg> && rm -rf /var/lib/apt/lists/*",
  'AVD-DS-0026': "# Declare a HEALTHCHECK:\nHEALTHCHECK --interval=30s CMD curl -fsS http://localhost/ || exit 1",
  // Kubernetes (KSV) — locally verified: a maximally-bad Pod fires 19 of prod's KSV
  // rules, and the secured Pod these slices come from clears all 19 (trivy config).
  'AVD-KSV-0001': "# Disallow privilege escalation:\nsecurityContext:\n  allowPrivilegeEscalation: false",
  'AVD-KSV-0003': "# Drop all Linux capabilities (add back only what's needed):\nsecurityContext:\n  capabilities:\n    drop: [\"ALL\"]",
  'AVD-KSV-0004': "# Drop all Linux capabilities:\nsecurityContext:\n  capabilities:\n    drop: [\"ALL\"]",
  'AVD-KSV-0006': "# Do NOT mount the host docker.sock (container escape); use a PVC/emptyDir",
  'AVD-KSV-0011': "# Limit CPU:\nresources:\n  limits:\n    cpu: \"500m\"",
  'AVD-KSV-0012': "# Run as non-root:\nsecurityContext:\n  runAsNonRoot: true",
  'AVD-KSV-0013': "# Pin an immutable tag/digest, not :latest:\nimage: nginx:1.27.4",
  'AVD-KSV-0014': "# Read-only root filesystem:\nsecurityContext:\n  readOnlyRootFilesystem: true",
  'AVD-KSV-0015': "# Request CPU:\nresources:\n  requests:\n    cpu: \"100m\"",
  'AVD-KSV-0016': "# Request memory:\nresources:\n  requests:\n    memory: \"128Mi\"",
  'AVD-KSV-0018': "# Limit memory:\nresources:\n  limits:\n    memory: \"256Mi\"",
  'AVD-KSV-0020': "# Run with a high UID (> 10000):\nsecurityContext:\n  runAsUser: 10001",
  'AVD-KSV-0021': "# Run with a high GID (> 10000):\nsecurityContext:\n  runAsGroup: 10001",
  'AVD-KSV-0023': "# Remove hostPath volumes (node-filesystem escape); use emptyDir/PVC",
  'AVD-KSV-0030': "# Set the seccomp profile:\nsecurityContext:\n  seccompProfile:\n    type: RuntimeDefault",
  'AVD-KSV-0104': "# Enable seccomp:\nsecurityContext:\n  seccompProfile:\n    type: RuntimeDefault",
  'AVD-KSV-0106': "# Drop ALL capabilities; add back only NET_BIND_SERVICE if required:\nsecurityContext:\n  capabilities:\n    drop: [\"ALL\"]",
  'AVD-KSV-0110': "# Don't deploy into the default namespace:\nmetadata:\n  namespace: app",
  'AVD-KSV-0118': "# Set an explicit securityContext (runAsNonRoot + drop caps + read-only fs + seccomp)",
};

// Trivy emits rule IDs as both AVD-AZU-0008 and the short AZU-0008 across
// versions/checks. Normalize to the AVD-prefixed key for the lookup.
function iacFixKey(ruleId) {
  const id = String(ruleId || '').toUpperCase();
  if (id.startsWith('AVD-')) return id;
  if (/^(AZU|AWS|GCP|DS|KSV|KCV)-\d+/.test(id)) return `AVD-${id}`;
  return id;
}

/**
 * Suggested fix for an IaC misconfiguration. Returns an EXAMPLE-kind corrected
 * snippet for curated cloud rules, else null (the Resolution text already lives
 * in `remediation`, so we don't weakly duplicate it as a "fix"). Exported for
 * unit testing + reuse by the bicep engine path (both go through
 * normalizeTrivyConfigResults).
 */
export function suggestIacFix(ruleId) {
  const key = iacFixKey(ruleId);
  // Hand-verified overrides win (K8s/Docker locally-verified, Azure-Bicep for the
  // customer's IaC flavor) — then the authoritative Aqua-generated corpus.
  const curated = IAC_FIX_BY_RULE[key];
  if (curated) return { kind: 'EXAMPLE', code: curated };
  const gen = IAC_FIX_GENERATED[key];
  if (gen) return { kind: gen.kind, code: gen.code, ...(gen.lang ? { lang: gen.lang } : {}) };
  return null;
}

// ── IaC (trivy config) ───────────────────────────────────────────────────
/**
 * Normalize `trivy config --format json` output.
 *
 * Shape: { Results: [{ Target, Type, Misconfigurations: [{ ID, AVDID, Title,
 * Description, Message, Severity, Status, Resolution, References, PrimaryURL,
 * CauseMetadata: { StartLine } }] }] }
 *
 * Only `Status === 'FAIL'` rows become findings — Trivy also emits PASS rows
 * (every policy it evaluated) which are noise here. Severity is Trivy's
 * qualitative word, mapped through the shared bucket.
 */
export function normalizeTrivyConfigResults(json, { repoRoot = '' } = {}) {
  const results = json?.Results || [];
  const findings = [];
  for (const r of results) {
    const target = relativizePath(r?.Target || '', repoRoot) || null;
    const configType = r?.Type || null;
    for (const m of r?.Misconfigurations || []) {
      if (!m || !m.ID) continue;
      if (m.Status && m.Status !== 'FAIL') continue;
      const startLine = m.CauseMetadata?.StartLine;
      const endLineRaw = m.CauseMetadata?.EndLine;
      const line = Number.isInteger(startLine) && startLine > 0 ? startLine : null;
      // Trivy reports the full cause block (StartLine..EndLine). Carrying EndLine
      // makes the code snippet highlight the WHOLE offending block instead of just
      // the first line — so a "missing securityContext" check highlights the
      // container block and a "disallowed volume" check highlights the volumes
      // section, lining the snippet up with the remediation. (SAST already does
      // this via ast-grep's range.) Capped at +20 lines so a giant resource
      // doesn't produce a wall-of-code snippet.
      const endLine =
        line && Number.isInteger(endLineRaw) && endLineRaw > line
          ? Math.min(endLineRaw, line + 20)
          : undefined;
      const finding = {
        type: FINDING_TYPES.IAC,
        ruleId: m.ID, // DS-0001, AVD-AWS-0086, …
        ruleName: clip(m.Title || m.ID, 300),
        severity: normalizeSeverityWord(m.Severity),
        file: target,
        line,
        column: null,
        description: clip(m.Message || m.Description || m.Title || m.ID),
        remediation: clip(m.Resolution || 'See the linked advisory for remediation guidance.', 1000),
        cveId: null,
        packageName: null,
        packageEcosystem: null,
        packageVersion: null,
        fixedVersion: null,
        cwe: null,
        evidence: {
          engine: 'trivy-config',
          ...(endLine ? { endLine } : {}),
          checkId: m.ID,
          avdId: m.AVDID || null,
          configType,
          primaryUrl: m.PrimaryURL || null,
          references: Array.isArray(m.References) ? m.References.slice(0, 5) : [],
          // Fix block, 100% coverage (parity floor): a corrected-code EXAMPLE for
          // checks in the curated/generated corpus, else Trivy's Resolution as
          // GUIDANCE text. Never empty, never a wrong snippet.
          ...((() => {
            const codeFix = suggestIacFix(m.ID);
            const fix = codeFix || (m.Resolution ? { kind: 'GUIDANCE', code: clip(m.Resolution, 600) } : null);
            return fix ? { fix } : {};
          })()),
        },
      };
      finding.identityKey = buildIdentityKey(finding);
      findings.push(finding);
    }
  }
  return findings;
}

// ── Container (Dockerfile base images via `trivy image`) ─────────────────────
//
// Parse a Dockerfile's FROM lines into the EXTERNAL base images worth scanning.
// Skips: build-stage aliases (`FROM <prior-stage>`), `scratch`, and unresolved
// ARG/variable images (`FROM ${BASE}` — we can't pull a variable). Returns
// `[{ image, line }]` with the 1-indexed FROM line for the finding location.
export function parseDockerfileFromImages(text) {
  const lines = String(text || '').split('\n');
  const stages = new Set(); // `AS <name>` aliases — internal, not pullable
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
    if (!m) continue;
    const image = m[1];
    const alias = m[2];
    const lower = image.toLowerCase();
    if (alias) stages.add(alias.toLowerCase());
    if (stages.has(lower)) continue;            // FROM <earlier-stage>
    if (lower === 'scratch') continue;           // empty base, nothing to scan
    if (/\$\{?\w+/.test(image)) continue;        // FROM ${BASE} — unresolved ARG
    // ARGUMENT INJECTION (2026-09-02). `(\S+)` happily captures a token starting
    // with `-`, and the image is passed to trivy as the last positional. Trivy
    // uses cobra/pflag, which parses flags interspersed with positionals, so a
    // repo committing `FROM --config=./evil.yaml` made trivy read ITS config —
    // handing the scanned repository control of server.addr (redirect the scan,
    // forge verdicts), module.dir + WASM modules, registry credentials and
    // insecure. Verified against the real binary: `FROM --generate-default-config`
    // in that slot wrote a file. A `--` separator is added at the call site too;
    // this is the other half, so a future caller cannot reopen it.
    if (image.startsWith('-')) continue;
    out.push({ image, line: i + 1 });
  }
  // De-duplicate by image, keeping the first FROM line.
  const seen = new Set();
  return out.filter((e) => (seen.has(e.image) ? false : seen.add(e.image)));
}

// Normalize one `trivy image --format json` report for a SINGLE base image into
// CONTAINER findings. `dockerfile` + `line` locate the FROM in the repo so the
// UI can deep-link; `image` is the scanned base image ref.
export function normalizeTrivyImageResults(json, { image, dockerfile = null, line = null } = {}) {
  const results = json?.Results || [];
  const findings = [];
  for (const r of results) {
    for (const v of r?.Vulnerabilities || []) {
      if (!v || !v.VulnerabilityID || !v.PkgName) continue;
      const finding = {
        type: FINDING_TYPES.CONTAINER,
        ruleId: v.VulnerabilityID, // CVE-… / GHSA-…
        ruleName: clip(v.Title || `${v.PkgName} ${v.VulnerabilityID}`, 300),
        severity: normalizeSeverityWord(v.Severity),
        file: dockerfile,
        line,
        column: null,
        description: clip(v.Description || v.Title || v.VulnerabilityID),
        remediation: v.FixedVersion
          ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later — rebuild on a patched base image (${image}).`
          : `No fixed version published. Track ${v.VulnerabilityID} or switch to a base image without ${v.PkgName}.`,
        cveId: /^CVE-/i.test(v.VulnerabilityID) ? v.VulnerabilityID : null,
        packageName: v.PkgName,
        packageEcosystem: r?.Type || null, // debian | alpine | gobinary | npm …
        packageVersion: v.InstalledVersion || null,
        fixedVersion: v.FixedVersion || null,
        cwe: Array.isArray(v.CweIDs) && v.CweIDs.length ? v.CweIDs[0] : null,
        dockerImage: image,
        evidence: {
          engine: 'trivy-image',
          image,
          target: r.Target || null,
          class: r.Class || null,
          primaryUrl: v.PrimaryURL || null,
        },
      };
      finding.identityKey = buildIdentityKey(finding);
      findings.push(finding);
    }
  }
  return findings;
}

// ── DAST (Nuclei) ──────────────────────────────────────────────────────────
//
// Normalize `nuclei -jsonl` output — one JSON object per matched template. Shape:
// { 'template-id', info: { name, severity, description, remediation, tags,
//   reference, classification: { 'cwe-id': ['cwe-79'], 'cve-id': ['CVE-…'],
//   'cvss-score' } }, type, host, 'matched-at', 'matcher-name',
//   'extracted-results' }.
//
// Severity: prefer the CVSS score bucket, else Nuclei's qualitative word.
// Nuclei 'info' is a RATING (its lowest real tier — e.g. missing security
// headers, cache-control, suspicious comments), NOT "severity unknown". Our
// FindingSeverity enum has no INFO tier, so 'info' maps to LOW (matching
// SEVERITY_BY_ASTGREP, where ast-grep 'info' already → LOW). Only Nuclei's
// explicit 'unknown' stays UNKNOWN. Pure-recon templates (tech/waf/ssl
// fingerprints) are low-signal noise — filtered by tag upstream, not by
// burying them in UNKNOWN.
//
// SECURITY: `extracted-results` can echo live response content, so it is clipped
// (80 chars × max 5) — never store raw/large extracted payloads.
const NUCLEI_SEVERITY = {
  critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'LOW', unknown: 'UNKNOWN',
};

function stripQuery(u) {
  if (!u) return '';
  const i = u.indexOf('?');
  return i === -1 ? u : u.slice(0, i);
}

function firstCwe(cls) {
  const arr = cls?.['cwe-id'];
  if (!Array.isArray(arr) || !arr.length) return null;
  const m = String(arr[0]).match(/\d+/);
  return m ? `CWE-${m[0]}` : null;
}

function firstCve(cls) {
  const arr = cls?.['cve-id'];
  if (!Array.isArray(arr)) return null;
  return arr.find((c) => typeof c === 'string' && /^CVE-/i.test(c))?.toUpperCase() || null;
}

export function normalizeNucleiResults(records, { target } = {}) {
  const list = Array.isArray(records) ? records : [];
  const findings = [];
  for (const r of list) {
    const templateId = r?.['template-id'];
    if (!templateId) continue;
    const info = r?.info || {};
    const cls = info.classification || {};
    const matchedUrl = r?.['matched-at'] || r?.host || target || '';
    const matcherName = r?.['matcher-name'] || null;
    const cvssSeverity = cvssScoreToSeverity(cls['cvss-score']);
    const severity =
      cvssSeverity !== 'UNKNOWN'
        ? cvssSeverity
        : NUCLEI_SEVERITY[String(info.severity || '').toLowerCase()] || 'UNKNOWN';
    const tags = Array.isArray(info.tags)
      ? info.tags
      : typeof info.tags === 'string'
        ? info.tags.split(',').map((t) => t.trim())
        : [];
    const extracted = Array.isArray(r?.['extracted-results'])
      ? r['extracted-results'].slice(0, 5).map((e) => clip(String(e), 80))
      : [];

    const finding = {
      type: FINDING_TYPES.DAST,
      ruleId: templateId,
      ruleName: clip(info.name || templateId, 300),
      severity,
      file: null,
      line: null,
      column: null,
      targetUrl: clip(matchedUrl, 500),
      matchedUrl, // consumed by buildIdentityKey; not a DB column
      matcherName, // consumed by buildIdentityKey; not a DB column
      description: clip(info.description || info.name || templateId),
      remediation: clip(
        info.remediation ||
          (Array.isArray(info.reference) && info.reference.length
            ? `See: ${info.reference.slice(0, 3).join(', ')}`
            : null) ||
          null,
        1000
      ),
      cveId: firstCve(cls),
      packageName: null,
      packageEcosystem: null,
      packageVersion: null,
      fixedVersion: null,
      cwe: firstCwe(cls),
      evidence: {
        engine: 'nuclei',
        templateId,
        matchedAt: clip(matchedUrl, 500),
        matcherName,
        protocol: r?.type || null, // http | dns | ssl | tcp …
        tags: tags.slice(0, 12),
        cvssScore: Number.isFinite(Number(cls['cvss-score'])) ? Number(cls['cvss-score']) : null,
        reference: Array.isArray(info.reference) ? info.reference.slice(0, 5) : [],
        extracted,
      },
    };
    finding.identityKey = buildIdentityKey(finding);
    delete finding.matchedUrl; // consumed by buildIdentityKey; not a DB column
    delete finding.matcherName;
    findings.push(finding);
  }
  return findings;
}

// ── ZAP (OWASP ZAP active/passive DAST) ──────────────────────────────────────
// ZAP riskcode → canonical severity. ZAP: 3=High, 2=Medium, 1=Low,
// 0=Informational. FindingSeverity has no INFO tier, so 0=Informational maps to
// LOW (a rating, not "unknown" — mirrors the nuclei info→LOW + ast-grep info→LOW
// convention). Genuinely-unrated findings are the only ones that stay UNKNOWN.
const ZAP_RISK_SEVERITY = { 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW', 0: 'LOW' };
const ZAP_CONFIDENCE = { 0: 'false-positive', 1: 'low', 2: 'medium', 3: 'high', 4: 'confirmed' };

// ZAP `desc`/`solution`/`reference` are HTML fragments (<p>…</p>). Strip tags,
// decode the handful of entities ZAP emits, and collapse whitespace.
function stripHtml(s) {
  if (!s || typeof s !== 'string') return '';
  return s
    .replace(/<\/?(p|br|ul|ol|li|pre|code|b|i|strong|em|a|div|span)\b[^>]*>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"').replace(/&#x?[0-9a-fA-F]+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Normalize an OWASP ZAP "traditional-json" report into AppSecFinding-shaped
 * DAST rows. One finding per alert type (ZAP already groups instances); the
 * first instance supplies the URL + param for identity + evidence. No response
 * bodies are ever included — only the attack vector + matched evidence string.
 *
 * @param {object} report  parsed ZAP traditional-json (`{ site: [{ alerts:[...] }] }`)
 * @param {object} [opts]
 * @param {string} [opts.target]  scanned URL (fallback when an alert has no instance)
 * @returns {Array} normalized type=DAST findings
 */
export function normalizeZapResults(report, { target } = {}) {
  const sites = Array.isArray(report?.site) ? report.site : [];
  const findings = [];
  for (const site of sites) {
    const alerts = Array.isArray(site?.alerts) ? site.alerts : [];
    for (const a of alerts) {
      const ruleId = a?.alertRef || a?.pluginid;
      if (!ruleId) continue;
      const instances = Array.isArray(a?.instances) ? a.instances : [];
      const first = instances[0] || {};
      const matchedUrl = first.uri || a.uri || site['@name'] || target || '';
      const param = first.param || null;
      const severity = ZAP_RISK_SEVERITY[Number(a.riskcode)] || 'UNKNOWN';
      const cweNum = Number(a.cweid);
      const cwe = Number.isInteger(cweNum) && cweNum > 0 ? `CWE-${cweNum}` : null;

      const finding = {
        type: FINDING_TYPES.DAST,
        ruleId: String(ruleId),
        ruleName: clip(a.alert || ruleId, 300),
        severity,
        file: null,
        line: null,
        column: null,
        targetUrl: clip(matchedUrl, 500),
        matchedUrl, // consumed by buildIdentityKey; not a DB column
        matcherName: param, // param distinguishes multiple hits of one rule on one URL
        description: clip(stripHtml(a.desc) || a.alert || String(ruleId)),
        remediation: clip(stripHtml(a.solution) || 'See the linked references for remediation guidance.', 1000),
        cveId: null,
        packageName: null,
        packageEcosystem: null,
        packageVersion: null,
        fixedVersion: null,
        cwe,
        evidence: {
          engine: 'zap',
          pluginId: a.pluginid || null,
          alertRef: a.alertRef || null,
          confidence: ZAP_CONFIDENCE[Number(a.confidence)] || null,
          count: Number.isFinite(Number(a.count)) ? Number(a.count) : instances.length,
          // up to 5 concrete instances (url/method/param/attack/evidence) — the
          // "where + how". NEVER a response body.
          instances: instances.slice(0, 5).map((i) => ({
            uri: clip(i.uri || '', 500),
            method: i.method || null,
            param: i.param || null,
            attack: clip(i.attack || '', 300) || null,
            evidence: clip(i.evidence || '', 300) || null,
          })),
          cweid: a.cweid || null,
          wascid: a.wascid || null,
          reference: stripHtml(a.reference).split(' ').filter((u) => /^https?:\/\//.test(u)).slice(0, 5),
        },
      };
      finding.identityKey = buildIdentityKey(finding);
      delete finding.matchedUrl;
      delete finding.matcherName;
      findings.push(finding);
    }
  }
  return findings;
}

function relativizePath(p, repoRoot) {
  if (!p) return '';
  if (repoRoot && p.startsWith(repoRoot)) {
    return p.slice(repoRoot.length).replace(/^\/+/, '');
  }
  return p;
}

// ── SBOM (CycloneDX) ─────────────────────────────────────────────────────────
// Parse the `components[]` of a CycloneDX 1.x document (Trivy `--format
// cyclonedx`) into SBOM package rows. Each component → {purl, name, version,
// ecosystem, license}. The root application component (`type: 'application'`
// or the `metadata.component` bom-ref) is skipped — we want dependencies.
//
// License extraction handles both CycloneDX license shapes:
//   licenses: [{ license: { id | name } }, { expression: 'MIT OR Apache-2.0' }]
// Ecosystem comes from the PURL type (pkg:npm/… → 'npm') with a fallback to
// Trivy's `aquasecurity:trivy:PkgType` property.

/** Extract a ';'-joined license string from a CycloneDX component. */
function cycloneDxLicense(component) {
  const arr = component?.licenses;
  if (!Array.isArray(arr) || arr.length === 0) return null;
  const parts = [];
  for (const entry of arr) {
    if (!entry) continue;
    if (typeof entry.expression === 'string' && entry.expression.trim()) {
      parts.push(entry.expression.trim());
    } else if (entry.license) {
      const id = entry.license.id || entry.license.name;
      if (id && String(id).trim()) parts.push(String(id).trim());
    }
  }
  if (parts.length === 0) return null;
  const seen = new Set();
  const uniq = parts.filter((p) => (seen.has(p) ? false : (seen.add(p), true)));
  return clip(uniq.join('; '), 500);
}

/** Ecosystem (PURL type) for a component, e.g. 'pkg:npm/lodash@4' → 'npm'. */
function cycloneDxEcosystem(component) {
  const purl = component?.purl;
  if (typeof purl === 'string') {
    const m = /^pkg:([^/]+)\//.exec(purl);
    if (m) return m[1].toLowerCase();
  }
  const props = component?.properties;
  if (Array.isArray(props)) {
    const t = props.find((p) => p?.name === 'aquasecurity:trivy:PkgType');
    if (t?.value) return String(t.value).toLowerCase();
  }
  return null;
}

/**
 * Parse a CycloneDX document into SBOM package rows.
 * @param {object} json  parsed CycloneDX JSON (Trivy `fs --format cyclonedx`)
 * @returns {Array<{purl:string,name:string,version:string|null,ecosystem:string|null,license:string|null}>}
 */
export function parseCycloneDxComponents(json) {
  const components = Array.isArray(json?.components) ? json.components : [];
  const rootRef = json?.metadata?.component?.['bom-ref'];
  const out = [];
  const seen = new Set();
  for (const c of components) {
    if (!c || !c.name) continue;
    // Skip the root application / OS component — not a dependency.
    if (c.type === 'application' || c.type === 'operating-system') continue;
    if (rootRef && c['bom-ref'] === rootRef) continue;
    // Dedup key prefers the purl; fall back to name@version.
    const purl = c.purl || (c.version ? `${c.name}@${c.version}` : c.name);
    if (seen.has(purl)) continue;
    seen.add(purl);
    out.push({
      purl: clip(purl, 1000),
      name: clip(c.name, 500),
      version: c.version ? clip(String(c.version), 200) : null,
      ecosystem: cycloneDxEcosystem(c),
      license: cycloneDxLicense(c),
    });
  }
  return out;
}
