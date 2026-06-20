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
});

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
        const severity =
          cvssScoreToSeverity(group?.max_severity) !== 'UNKNOWN'
            ? cvssScoreToSeverity(group?.max_severity)
            : normalizeSeverityWord(vuln?.database_specific?.severity);

        const cveId =
          (vuln.id.startsWith('CVE-') && vuln.id) ||
          (vuln.aliases || []).find((a) => typeof a === 'string' && a.startsWith('CVE-')) ||
          null;
        const fixedVersion = extractFixedVersion(vuln, { name, ecosystem });

        const finding = {
          type: FINDING_TYPES.SCA,
          ruleId: vuln.id, // OSV id (GHSA-…, GO-…, or CVE-…)
          ruleName: clip(vuln.summary || vuln.id, 300),
          severity,
          file: sourcePath || null,
          line: null,
          column: null,
          description: clip(vuln.summary || vuln.details || vuln.id),
          remediation: fixedVersion
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
          },
        };
        finding.identityKey = buildIdentityKey(finding);
        findings.push(finding);
      }
    }
  }
  return findings;
}

/** First published fixed version for the matching (ecosystem, package). */
function extractFixedVersion(vuln, { name, ecosystem }) {
  for (const affected of vuln?.affected || []) {
    const pkg = affected?.package || {};
    if (pkg.name !== name) continue;
    if (ecosystem && pkg.ecosystem && pkg.ecosystem !== ecosystem) continue;
    for (const range of affected?.ranges || []) {
      for (const event of range?.events || []) {
        if (event?.fixed) return event.fixed;
      }
    }
  }
  return null;
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
};

/**
 * Produce a suggested fix for a SAST finding.
 *  - AUTOFIX: a deterministic mechanical rewrite of the matched snippet (weak
 *    crypto → SHA-256, disabled TLS verify → enabled, mktemp → mkstemp). The
 *    `code` is a true before→after replacement of `matched`.
 *  - EXAMPLE: a canonical secure pattern for injection classes with no safe
 *    mechanical rewrite.
 * Returns null when neither applies. `matched` is the exact matched substring.
 */
export function suggestSastFix(cwe, matched) {
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
  const example = SAST_FIX_EXAMPLE_BY_CWE[cwe];
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
        fix: suggestSastFix(cwe, m.text),
      },
    };
    finding.identityKey = buildIdentityKey(finding);
    findings.push(finding);
  }
  return findings;
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
// Severity: prefer the CVSS score bucket, else Nuclei's qualitative word. Nuclei
// 'info' (tech detection / fingerprints) maps to UNKNOWN — real but low-signal;
// the UI deprioritizes it (the noise-reduction posture Aikido/Cycode lead on).
//
// SECURITY: `extracted-results` can echo live response content, so it is clipped
// (80 chars × max 5) — never store raw/large extracted payloads.
const NUCLEI_SEVERITY = {
  critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'UNKNOWN', unknown: 'UNKNOWN',
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
// 0=Informational. FindingSeverity has no INFO, so informational collapses to
// UNKNOWN (same as the nuclei info-tier).
const ZAP_RISK_SEVERITY = { 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW', 0: 'UNKNOWN' };
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
