// Secrets engine — gitleaks (MIT). NOT TruffleHog — AGPL, license-blocked.
//
// Full-history scan (`--log-opts=--all`): walks every commit on every ref,
// catching deleted-but-committed secrets that a working-tree scan misses.
// Same binary as our .husky pre-commit hook, different invocation.
//
// SECURITY: `--redact` keeps secret values out of gitleaks' own logs, and the
// normalizer (src/normalize.js#normalizeGitleaksResults) drops Secret/Match
// before anything reaches the DB. Plumb-line rule: the leaked value never
// leaves the scan container.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { normalizeGitleaksResults } from '../normalize.js';

const execFileAsync = promisify(execFile);

// Build a gitleaks config that keeps the built-in rules (extend.useDefault) but
// adds the org's allowlist regexes — matches treated as non-secrets and never
// surfaced. Regexes containing the TOML literal delimiter are dropped (can't be
// safely embedded) rather than risk a malformed config. The allowlist applies to
// the matched secret VALUE, which we never store, so it MUST run at scan time.
function buildGitleaksConfig(allowlistRegexes) {
  const safe = (allowlistRegexes || [])
    .filter((r) => typeof r === 'string' && r.trim() && !r.includes("'''"))
    .map((r) => `  '''${r.trim()}''',`);
  return [
    'title = "shadow-span-appsec"',
    '[extend]',
    'useDefault = true',
    '[allowlist]',
    'regexTarget = "match"',
    'regexes = [',
    ...safe,
    ']',
    '',
  ].join('\n');
}

// Full-history scans on old repos are slow (plan risk #3) — generous ceiling,
// overridable per deployment.
const GITLEAKS_TIMEOUT_MS = parseInt(
  process.env.APPSEC_GITLEAKS_TIMEOUT_MS || `${30 * 60 * 1000}`,
  10
);

/**
 * Run gitleaks full-history against a git checkout.
 * @returns {Promise<Array>} normalized AppSecFinding-shaped rows (type=SECRET)
 */
export async function scanSecrets(repoPath, { allowlistRegexes = [] } = {}) {
  const workDir = await mkdtemp(path.join(tmpdir(), 'appsec-gitleaks-'));
  const reportPath = path.join(workDir, 'gitleaks-report.json');
  try {
    const args = [
      'git',
      repoPath,
      '--log-opts=--all',
      '--report-format', 'json',
      '--report-path', reportPath,
      '--redact',
      '--no-banner',
      // Leaks found is a successful scan, not a process failure.
      '--exit-code', '0',
    ];
    if (allowlistRegexes && allowlistRegexes.length) {
      const cfgPath = path.join(workDir, 'gitleaks.toml');
      await writeFile(cfgPath, buildGitleaksConfig(allowlistRegexes), 'utf8');
      args.push('--config', cfgPath);
    }
    await execFileAsync('gitleaks', args, {
      timeout: GITLEAKS_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
    }).catch((err) => {
      throw new Error(`gitleaks failed (code=${err.code}): ${truncate(err.stderr || err.message)}`);
    });

    const raw = await readFile(reportPath, 'utf8');
    const json = JSON.parse(raw);
    return normalizeGitleaksResults(json, { repoRoot: repoPath });
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

function truncate(s, max = 500) {
  return String(s || '').slice(0, max);
}
