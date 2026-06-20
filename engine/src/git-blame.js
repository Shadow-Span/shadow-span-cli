// Per-finding git blame — attaches the introducing commit (sha/author/date/
// summary) for the offending line to `evidence.commit`. Answers "who introduced
// this, and when" in the finding detail, the way enterprise SAST tools do.
//
// SAST + IaC only. SECRET findings already carry their commit from gitleaks and
// must NOT be blamed here (we deliberately keep secret evidence minimal).
//
// Efficiency: blame is run ONCE per unique file (full-file `--porcelain`) and
// indexed by line, so a file with many findings costs one git process.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const BLAME_TIMEOUT_MS = parseInt(process.env.APPSEC_BLAME_TIMEOUT_MS || '60000', 10);

/**
 * Parse `git blame --porcelain` into { byLine: {n: sha}, meta: {sha: {...}} }.
 * Porcelain emits a `<sha> <orig> <final> [<count>]` header before each line;
 * commit metadata (author / author-time / summary) appears the first time a sha
 * is seen and is cached by sha thereafter.
 */
export function parseBlamePorcelain(out) {
  const byLine = {};
  const meta = {};
  let sha = null;
  let finalLine = null;
  for (const raw of String(out || '').split('\n')) {
    const h = raw.match(/^([0-9a-f]{40}) \d+ (\d+)/);
    if (h) {
      sha = h[1];
      finalLine = parseInt(h[2], 10);
      if (!meta[sha]) meta[sha] = {};
      continue;
    }
    if (!sha) continue;
    if (raw.startsWith('author ')) meta[sha].author = raw.slice(7);
    else if (raw.startsWith('author-time ')) meta[sha].authorTime = parseInt(raw.slice(12), 10);
    else if (raw.startsWith('summary ')) meta[sha].summary = raw.slice(8);
    else if (raw[0] === '\t' && finalLine) byLine[finalLine] = sha; // the source line
  }
  return { byLine, meta };
}

/** Mutates each SAST/IaC finding in place, adding `evidence.commit`. */
export async function attachBlame(findings, repoRoot) {
  const cache = new Map(); // file -> parsed | null

  for (const f of findings || []) {
    if (!f || !f.file || !Number.isInteger(f.line) || f.line < 1) continue;

    let parsed = cache.get(f.file);
    if (parsed === undefined) {
      try {
        const { stdout } = await execFileAsync(
          'git',
          ['-C', repoRoot, 'blame', '--porcelain', '--', f.file],
          { timeout: BLAME_TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024 },
        );
        parsed = parseBlamePorcelain(stdout);
      } catch {
        parsed = null; // uncommitted / unreadable / binary — skip blame
      }
      cache.set(f.file, parsed);
    }
    if (!parsed) continue;

    const sha = parsed.byLine[f.line];
    if (!sha) continue;
    const m = parsed.meta[sha] || {};
    // The all-zero sha is git's "not yet committed" sentinel — skip it.
    if (/^0+$/.test(sha)) continue;

    f.evidence = {
      ...(f.evidence || {}),
      commit: {
        sha,
        shortSha: sha.slice(0, 8),
        author: m.author || null,
        // ISO date from the unix author-time (no PII email stored).
        date: Number.isFinite(m.authorTime) ? new Date(m.authorTime * 1000).toISOString() : null,
        summary: m.summary ? m.summary.slice(0, 120) : null,
      },
    };
  }
  return findings;
}
