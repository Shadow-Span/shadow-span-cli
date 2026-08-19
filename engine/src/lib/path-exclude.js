// Glob path exclusions for AppSec scans — ONE engine-agnostic post-scan filter so
// a single rule (**/test/fixtures/**, vendor/**, *.min.js) drops findings from EVERY
// engine, regardless of which produced the path. Cleaner + more uniform than
// teaching each engine (osv-scanner has no path-exclude flag, gitleaks/trivy each
// differ) its own exclusion syntax.
//
// Glob semantics (gitignore-lite): `*` = any chars except `/`, `**` = any chars
// incl `/`, `?` = one char except `/`. A pattern with NO slash matches the
// BASENAME at any depth (so `*.min.js` excludes `a/b/x.min.js`); a pattern WITH a
// slash matches the full repo-relative path, ANCHORED AT THE REPO ROOT.
//
// That anchoring is the sharp edge: `test/fixtures/**` matches ONLY a root-level
// test/ dir, so on a monorepo it silently excludes nothing — the author wanted
// `**/test/fixtures/**`. A pattern that matches nothing is indistinguishable from
// one that works, which is why explainExclusions() exists: callers can show the
// per-pattern hit count and surface an inert rule instead of leaving it to be
// discovered when a finding everyone thought was excluded shows up in a report.

// `**` is parked on U+0000 while single `*` is translated, then expanded. NUL can
// never occur in a real path, so it is a safe placeholder — but it is written as an
// ESCAPE, not a raw byte: a literal NUL makes git classify this file as binary and
// silently show an EMPTY diff for it.
const DOUBLESTAR = '\u0000';

export function compileExclusions(globs) {
  return (globs || [])
    .filter((g) => typeof g === 'string' && g.trim())
    .map((raw) => {
      const g = raw.trim();
      const hasSlash = g.includes('/');
      const re = g
        .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex specials (not * ? )
        .replace(/\*\*/g, DOUBLESTAR) // placeholder so the next step doesn't touch it
        .replace(/\*/g, '[^/]*')
        // `?` is translated HERE, before the optional groups below are inserted. Those
        // contain a literal `?`, so running this step last rewrote `(?:.*/)?` into
        // `([^/]:.*/)[^/]` and every `**/` pattern silently stopped matching.
        .replace(/\?/g, '[^/]')
        // `**/` spans ZERO OR MORE directories, per gitignore: "A leading '**' followed by a
        // slash means match in all directories ... '**/foo' matches file or directory 'foo'
        // anywhere, the same as pattern 'foo'." and "a/**/b" matches "a/b".
        // https://git-scm.com/docs/gitignore
        // Translating it as a plain `.*` leaves the slash MANDATORY, so `**/test/fixtures/**`
        // missed a ROOT-level test/fixtures/ — the same silent no-op this module exists to
        // prevent, reintroduced by the very fix we tell authors to apply.
        .replace(new RegExp(`^${DOUBLESTAR}/`), '(?:.*/)?')
        .replace(new RegExp(`/${DOUBLESTAR}/`, 'g'), '/(?:.*/)?')
        .replace(new RegExp(DOUBLESTAR, 'g'), '.*');
      return { glob: g, re: new RegExp('^' + re + '$'), basename: !hasSlash };
    });
}

export function isPathExcluded(file, compiled) {
  if (!file || !compiled || !compiled.length) return false;
  const full = String(file).replace(/^\.?\//, '');
  const base = full.split('/').pop();
  return compiled.some((c) => c.re.test(c.basename ? base : full));
}

/**
 * Directories that hold FETCHED THIRD-PARTY CODE rather than the author's own. Always excluded,
 * because a finding in one is not actionable through this channel: the user cannot edit
 * node_modules: the remedy for a vulnerable dependency is an SCA upgrade driven by the lockfile,
 * which these globs deliberately do not touch (lockfiles live at the project root, not inside
 * node_modules).
 *
 * WHY IT IS A DEFAULT AND NOT DOCUMENTATION. Until 0.1.1 the engines only skipped node_modules
 * when the target happened to be a git repo, because the underlying tools consult git's index —
 * a .gitignore alone did NOT do it. Verified on the published 0.1.0:
 *     plain directory        → 2 findings from node_modules
 *     .gitignore node_modules/ → 2   (ignored)
 *     git init               → 0
 * So the very first thing a new user does — npm i the CLI, scan a folder — reported findings
 * against `node_modules/@shadow-span/cli/...`, i.e. the scanner accusing its own source. CI never
 * caught it because CI is always a git checkout.
 *
 * Conservative on purpose: only directories that are UNAMBIGUOUSLY fetched dependencies. `vendor/`
 * is deliberately absent — it is composer/Go deps in some projects and hand-written code in
 * others, so it stays a user-configured rule (and is already the documented example).
 */
export const DEFAULT_EXCLUSIONS = Object.freeze([
  '**/node_modules/**',
  '**/bower_components/**',
  '**/site-packages/**',
  '**/.venv/**',
  '**/venv/**',
  '**/Pods/**',
  '**/.git/**',
]);

/**
 * Drop findings whose file/lockfile path matches any exclusion glob. Findings
 * with no path (e.g. type=LICENSE) are never excluded.
 *
 * DEFAULT_EXCLUSIONS are applied in addition to `globs`. Pass
 * `{ includeDefaults: false }` to scan dependency trees deliberately — hunting a supply-chain
 * implant in node_modules is a real task, and this filter must not be the thing that prevents it.
 *
 * @param {Array} findings
 * @param {string[]} globs               user/org-configured exclusions
 * @param {{includeDefaults?: boolean}} [opts]
 * @returns {{ findings: Array, dropped: number }}
 */
export function applyPathExclusions(findings, globs, opts = {}) {
  const { includeDefaults = true } = opts;
  const all = includeDefaults ? [...DEFAULT_EXCLUSIONS, ...(globs || [])] : globs;
  const compiled = compileExclusions(all);
  if (!compiled.length) return { findings, dropped: 0 };
  const kept = findings.filter((f) => !isPathExcluded(f.file || f.evidence?.lockfile, compiled));
  // Return the ORIGINAL array when nothing matched. Callers relied on that identity before
  // defaults existed (a no-op scan handed back the same reference), and adding always-on globs
  // would otherwise allocate a new array on every clean scan for no reason.
  if (kept.length === findings.length) return { findings, dropped: 0 };
  return { findings: kept, dropped: findings.length - kept.length };
}

/**
 * Score each glob INDEPENDENTLY against a corpus of paths, so a caller can tell the
 * author which rules actually do something. Reported per-pattern rather than as one
 * total because overlapping rules otherwise hide each other: `**\/__tests__/**` looks
 * productive next to `**\/sast-fixtures/**` until you see that nearly all of its hits
 * are the same files.
 *
 * `inert: true` is the signal worth surfacing — the pattern is syntactically fine and
 * matched nothing, which is almost always root-anchoring (see the header note).
 *
 * NOTE: this measures against paths ALREADY OBSERVED. A pattern reported inert may
 * still match something a future scan finds, so it is a warning, never an error, and
 * nothing here may auto-delete a user's rule.
 *
 * @param {Array<{file: string, count?: number}>} entries corpus, count defaults to 1
 * @param {string[]} globs
 */
export function explainExclusions(entries, globs) {
  const rows = (entries || []).filter((e) => e && typeof e.file === 'string');
  const totalPaths = rows.length;
  const totalFindings = rows.reduce((a, r) => a + (Number(r.count) || 1), 0);

  const patterns = (globs || [])
    .filter((g) => typeof g === 'string' && g.trim())
    .map((g) => {
      let compiled;
      try {
        compiled = compileExclusions([g]);
      } catch {
        // A glob that will not compile can never exclude anything. Report it rather
        // than throwing — one bad line must not blank the whole preview.
        return { glob: g.trim(), paths: 0, findings: 0, inert: true, invalid: true };
      }
      const hit = rows.filter((r) => isPathExcluded(r.file, compiled));
      const findings = hit.reduce((a, r) => a + (Number(r.count) || 1), 0);
      return { glob: g.trim(), paths: hit.length, findings, inert: hit.length === 0, invalid: false };
    });

  const all = compileExclusions(globs);
  const matched = all.length ? rows.filter((r) => isPathExcluded(r.file, all)) : [];

  return {
    patterns,
    totalPaths,
    totalFindings,
    matchedPaths: matched.length,
    matchedFindings: matched.reduce((a, r) => a + (Number(r.count) || 1), 0),
    // Largest contributors, so the author can eyeball that the right things go.
    sample: matched
      .slice()
      .sort((a, b) => (Number(b.count) || 1) - (Number(a.count) || 1))
      .slice(0, 10)
      .map((r) => ({ file: r.file, count: Number(r.count) || 1 })),
  };
}
