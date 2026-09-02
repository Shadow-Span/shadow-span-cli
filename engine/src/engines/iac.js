// IaC engine — Trivy config (Apache-2.0). NOT KICS/Checkov: Trivy is a single
// self-contained binary (no external query-asset bundle to vendor into the
// image) and we already run it in services/cloud-security for container/image
// scanning. `trivy config` evaluates Trivy's built-in misconfiguration policies
// (Dockerfile, Terraform, CloudFormation, Kubernetes, Helm, etc.) against a
// directory — no separate rule pack to maintain for v1.
//
// Invocation: `trivy config --format json --output <file> <repo>`. Trivy writes
// the report to the file and exits 0 even when misconfigurations are found
// (unlike osv-scanner/ast-grep). `--exit-code` is left at its 0 default so a
// FAIL result is not treated as a process failure.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scannerEnv } from '../lib/scanner-env.js';

import { normalizeTrivyConfigResults } from '../normalize.js';
import { attachCodeContext } from '../code-context.js';
import { attachBlame } from '../git-blame.js';
import { finalStageIsNonRoot, ROOT_USER_CHECK_IDS } from '../lib/nonroot-base-images.js';

const execFileAsync = promisify(execFile);

const IAC_TIMEOUT_MS = parseInt(process.env.APPSEC_IAC_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

// Binary resolution: PATH first (Dockerfile installs the Trivy release binary
// into /usr/local/bin; locally `brew install trivy`). APPSEC_TRIVY_BIN overrides.
const TRIVY_BIN = process.env.APPSEC_TRIVY_BIN || 'trivy';

// Our own Rego rule pack (rules/iac/**/*.rego), authored in the `user` namespace.
// Runs ALONGSIDE Trivy's built-in checks (augment, don't fork) — built-ins cover
// the long tail, our SS-* rules close measured gaps (e.g. wildcard-admin IAM) and
// own the remediation/fix content. Compliance mappings for BOTH built-in and our
// findings are attached in normalize.js from rules/iac/mappings.json.
// Pack location: normally resolved relative to this module (…/appsec-engine/rules/iac).
// APPSEC_IAC_PACK_DIR overrides it — needed where the runtime can't reach the
// package's rules/ dir by relative path (e.g. the Next.js web standalone build,
// whose Turbopack tracer rejects out-of-project globs). There the Dockerfile
// copies the pack to a fixed path and points this env var at it.
const PACK_DIR = process.env.APPSEC_IAC_PACK_DIR
  || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'rules', 'iac');
const MAPPINGS_PATH = path.join(PACK_DIR, 'mappings.json');

// rule id → compliance-control mapping, loaded once from the pack sidecar. We
// attach it HERE (the engine wrapper already does I/O) rather than in
// normalize.js, which is a pure/no-I/O module by contract. Covers Trivy built-in
// AVD ids AND our SS-* ids, so every finding — built-in or ours — carries the
// frameworks/category it maps to (empty for the long-tail built-ins not yet
// promoted into mappings.json).
let _mappings;
async function loadMappings() {
  if (_mappings) return _mappings;
  try {
    _mappings = JSON.parse(await readFile(MAPPINGS_PATH, 'utf8'));
  } catch {
    _mappings = {}; // pack sidecar missing/corrupt → findings still flow, just unmapped
  }
  return _mappings;
}

/**
 * Run `trivy config` against a checked-out repo directory.
 * @returns {Promise<Array>} normalized AppSecFinding-shaped rows (type=IAC)
 */
export async function scanIac(repoPath) {
  const reportDir = await mkdtemp(path.join(tmpdir(), 'appsec-trivy-'));
  const reportPath = path.join(reportDir, 'config.json');
  try {
    const args = [
      'config',
      '--config-check', PACK_DIR,   // load our Rego pack (rules/iac/**) …
      '--check-namespaces', 'user', // …evaluated under the `user` namespace, alongside built-ins
      '--format', 'json',
      '--output', reportPath,
      '--quiet',          // suppress the progress/db-download chatter on stdout
      repoPath,
    ];
    try {
      await execFileAsync(TRIVY_BIN, args, {
        env: scannerEnv(), timeout: IAC_TIMEOUT_MS,
        maxBuffer: 32 * 1024 * 1024,
      });
    } catch (err) {
      // Trivy exits non-zero only on a real error (bad args, unreadable dir) —
      // a FAIL misconfiguration leaves exit 0. If the report still got written,
      // trust it; otherwise surface the error.
      let wrote = false;
      try { await readFile(reportPath); wrote = true; } catch { /* not written */ }
      if (!wrote) {
        throw new Error(`trivy config failed (code=${err.code}): ${truncate(err.stderr || err.message)}`);
      }
    }

    const raw = await readFile(reportPath, 'utf8');
    const json = raw.trim() ? JSON.parse(raw) : {};
    let findings = normalizeTrivyConfigResults(json, { repoRoot: repoPath });
    // DS-0002 ("Image user should not be 'root'") reads only Dockerfile instructions and never
    // resolves the base image's own config, so a final stage of e.g. distroless `:nonroot` — which
    // runs as uid 65532 — is reported as running as root. Drop those: the alternative is asking
    // people to add a USER line that changes nothing, which teaches them the scanner is wrong.
    // Unreadable or unrecognised base => finding KEPT. Never suppress on a guess.
    findings = (await Promise.all(findings.map(async (f) => {
      if (!ROOT_USER_CHECK_IDS.has(f.ruleId) || !f.file) return f;
      try {
        const df = await readFile(path.join(repoPath, f.file), 'utf8');
        return finalStageIsNonRoot(df) ? null : f;
      } catch { return f; }
    }))).filter(Boolean);
    // Attach compliance frameworks + category by rule id (built-in AVD or SS-*).
    const mappings = await loadMappings();
    for (const f of findings) {
      const m = mappings[f.ruleId] || mappings[f.evidence?.avdId];
      if (m) {
        if (m.frameworks) f.frameworks = m.frameworks;
        if (m.category) f.evidence.category = m.category;
      }
    }
    // Enrich with the ±3-line code window + the introducing commit (git blame).
    await attachCodeContext(findings, repoPath);
    await attachBlame(findings, repoPath);
    return findings;
  } finally {
    await rm(reportDir, { recursive: true, force: true }).catch(() => {});
  }
}

function truncate(s, max = 500) {
  return String(s || '').slice(0, max);
}
