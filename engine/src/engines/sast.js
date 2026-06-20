// SAST engine — ast-grep, a tree-sitter structural matcher. We ship our own
// rule packs (under engine/rules/sast/), authored against the OWASP Top 10 and
// CWE Top 25 for coverage.
//
// v1 scope = Tier-0 structural + simple single-file sinks: eval/exec code
// injection, weak crypto, disabled TLS verification, unsafe deserialization,
// React XSS sinks. Deep inter-procedural taint (data flow across functions) is
// a deliberate v2 decision and is out of scope here.
//
// Invocation: `ast-grep scan --config <rules>/sgconfig.yml --json=compact <repo>`
// → JSON array of matches on stdout. ast-grep exits non-zero when error-severity
// matches exist (linter convention); that's a successful scan, not a failure —
// stdout still holds the JSON.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { normalizeAstGrepResults } from '../normalize.js';
import { attachCodeContext } from '../code-context.js';
import { attachBlame } from '../git-blame.js';

const execFileAsync = promisify(execFile);

const SAST_TIMEOUT_MS = parseInt(process.env.APPSEC_SAST_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

// Rule pack ships under engine/rules/sgconfig.yml, resolved relative to this
// engine module (up two directories, then into rules/).
const RULES_CONFIG = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', 'rules', 'sgconfig.yml',
);

// Binary resolution: PATH first (the Dockerfile puts node_modules/.bin on PATH,
// where @ast-grep/cli installs the `ast-grep` shim; locally `brew install
// ast-grep`). APPSEC_ASTGREP_BIN overrides.
const ASTGREP_BIN = process.env.APPSEC_ASTGREP_BIN || 'ast-grep';

/**
 * Run our ast-grep rule pack against a checked-out repo directory.
 * @returns {Promise<Array>} normalized AppSecFinding-shaped rows (type=SAST)
 */
export async function scanSast(repoPath) {
  const args = ['scan', '--config', RULES_CONFIG, '--json=compact', repoPath];
  let stdout = '';
  try {
    ({ stdout } = await execFileAsync(ASTGREP_BIN, args, {
      timeout: SAST_TIMEOUT_MS,
      maxBuffer: 32 * 1024 * 1024,
    }));
  } catch (err) {
    // Non-zero exit with findings still writes the JSON array to stdout. Only a
    // spawn failure / empty stdout is a real error worth surfacing.
    if (err.stdout && err.stdout.trim()) {
      stdout = err.stdout;
    } else {
      throw new Error(`ast-grep failed (code=${err.code}): ${truncate(err.stderr || err.message)}`);
    }
  }

  const json = stdout.trim() ? JSON.parse(stdout) : [];
  const findings = normalizeAstGrepResults(json, { repoRoot: repoPath });
  // Enrich with the ±3-line code window + the introducing commit (git blame).
  await attachCodeContext(findings, repoPath);
  await attachBlame(findings, repoPath);
  return findings;
}

function truncate(s, max = 500) {
  return String(s || '').slice(0, max);
}
