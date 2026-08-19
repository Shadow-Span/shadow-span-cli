// .shadowspanignore — per-repo path exclusions (gitignore-style globs). Findings
// whose file matches an ignore pattern are dropped before gating + reporting, so
// intentional test fixtures, vendored code, generated dirs, etc. don't create
// noise or block the build.
//
// Zero-dependency (the CLI is self-contained). Supports the common gitignore
// subset — enough for real exclude lists, without a full gitignore engine:
//   - blank lines + `# comments` ignored
//   - `dir/`            → the directory and everything under it
//   - `*.ext` / `a*b`   → `*` matches within a path segment (not `/`)
//   - `**`              → matches across segments (e.g. `**/__fixtures__/**`)
//   - leading `/`       → anchored at the repo root (else matches at any depth)
//   - trailing `/`      → directory-only
//   - `!pattern`        → negation (re-include) — applied after, last match wins
//
// Paths are matched as POSIX, repo-relative (forward slashes).

import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const IGNORE_FILENAME = '.shadowspanignore';

// Translate one gitignore-ish pattern to a RegExp matching a repo-relative path.
function patternToRegExp(raw) {
  let p = raw.trim();
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith('/');
  if (anchored) p = p.slice(1);

  // Escape regex specials except * and /, then expand globs.
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') { re += '.*'; i++; if (p[i + 1] === '/') i++; }
      else re += '[^/]*';
    } else if ('\\^$+?.()|[]{}'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }

  // anchored → must start at root; unanchored → may start at any segment boundary.
  const head = anchored ? '^' : '(^|.*/)';
  // dir patterns + plain names match the entry AND everything under it.
  const tail = '(/.*)?$';
  return new RegExp(head + re + tail);
}

/**
 * Parse ignore-file text into { test(relPath) -> boolean, patterns }.
 * Last matching rule wins (so `!` negations can re-include).
 */
export function parseIgnore(text) {
  const rules = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const negate = t.startsWith('!');
    const body = negate ? t.slice(1) : t;
    if (!body) continue;
    rules.push({ negate, re: patternToRegExp(body), raw: t });
  }
  const test = (rel) => {
    const norm = String(rel || '').replace(/\\/g, '/').replace(/^\.\//, '');
    let ignored = false;
    for (const r of rules) {
      if (r.re.test(norm)) ignored = !r.negate;
    }
    return ignored;
  };
  // WHICH rule decided to suppress a path — not just whether one did. "142 findings suppressed"
  // is not actionable; "142 suppressed by `**`" is. Last match wins, same as `test`, so a later
  // negation correctly reports "not suppressed" (null) rather than the earlier rule that matched.
  const which = (rel) => {
    const norm = String(rel || '').replace(/\\/g, '/').replace(/^\.\//, '');
    let decided = null;
    for (const r of rules) {
      if (r.re.test(norm)) decided = r.negate ? null : r.raw;
    }
    return decided;
  };

  return { test, which, patterns: rules.map((r) => r.raw), count: rules.length };
}

/**
 * Load `.shadowspanignore` from a repo root. Returns a matcher that ignores
 * nothing if the file is absent.
 */
export async function loadIgnore(repoPath) {
  try {
    const text = await readFile(path.join(repoPath, IGNORE_FILENAME), 'utf8');
    return parseIgnore(text);
  } catch {
    return { test: () => false, patterns: [], count: 0 };
  }
}

/**
 * Split findings into kept vs ignored by their `file` path. Findings without a
 * file (repo-wide) are always kept.
 */
export function applyIgnore(findings, matcher) {
  const kept = [];
  let ignored = 0;
  // Per-rule tally, reported to the platform so a repo-local ignore file stops being a silent
  // channel. The org list stays authoritative for what the PLATFORM drops; this records what the
  // RUNNER dropped on top of it, and which rule did it.
  const byRule = new Map();
  for (const f of findings || []) {
    if (f.file && matcher.test(f.file)) {
      ignored++;
      const rule = (matcher.which ? matcher.which(f.file) : null) || '(unknown rule)';
      byRule.set(rule, (byRule.get(rule) || 0) + 1);
    } else {
      kept.push(f);
    }
  }
  return {
    kept,
    ignored,
    byRule: [...byRule.entries()]
      .map(([rule, count]) => ({ rule, count }))
      .sort((a, b) => b.count - a.count),
  };
}
