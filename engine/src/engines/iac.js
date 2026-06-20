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

import { normalizeTrivyConfigResults } from '../normalize.js';
import { attachCodeContext } from '../code-context.js';
import { attachBlame } from '../git-blame.js';

const execFileAsync = promisify(execFile);

const IAC_TIMEOUT_MS = parseInt(process.env.APPSEC_IAC_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

// Binary resolution: PATH first (Dockerfile installs the Trivy release binary
// into /usr/local/bin; locally `brew install trivy`). APPSEC_TRIVY_BIN overrides.
const TRIVY_BIN = process.env.APPSEC_TRIVY_BIN || 'trivy';

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
      '--format', 'json',
      '--output', reportPath,
      '--quiet',          // suppress the progress/db-download chatter on stdout
      repoPath,
    ];
    try {
      await execFileAsync(TRIVY_BIN, args, {
        timeout: IAC_TIMEOUT_MS,
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
    const findings = normalizeTrivyConfigResults(json, { repoRoot: repoPath });
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
