// AppSec suppression-rule kernel (pure — no Prisma, no I/O).
//
// Org/repo-scoped rules let an analyst suppress whole classes of findings at
// READ time (e.g. "suppress everything under test/**", "suppress dev-only
// CVEs in ecosystem npm", "suppress rule SAST:xxx repo-wide"). Nothing is
// mutated — a rule just predicates rows OUT of the default view, so it is
// reversible and retroactive.
//
// HARD RULE: MALWARE is NEVER suppressible. A malicious dependency is an
// incident regardless of any rule — both findingMatchesRule() and the
// buildSuppressionWhere() predicate exclude type=MALWARE unconditionally.

export const SUPPRESSION_SCOPES = ['ORG', 'REPO'];
export const SUPPRESSION_MATCH_TYPES = ['RULE_ID', 'PATH_GLOB', 'PACKAGE', 'ECOSYSTEM', 'CWE', 'FINDING_TYPE'];

/** A rule is active if it has no expiry or the expiry is in the future. */
export function isRuleActive(rule, now = new Date()) {
  if (!rule) return false;
  if (!rule.expiresAt) return true;
  return new Date(rule.expiresAt).getTime() > new Date(now).getTime();
}

// Bounds on a glob we will compile to a regex. `.*` sequences backtrack
// exponentially in the number of wildcards, so the exponent is capped rather
// than left to whoever wrote the rule. Real globs use one or two wildcards;
// 8 is far past any legitimate pattern and keeps the worst case in single-digit
// milliseconds (measured: 8 wildcards ~7ms, 12 ~13s, 14 ~135s).
export const MAX_GLOB_LEN = 200;
export const MAX_GLOB_WILDCARDS = 8;

// Minimal, predictable glob → matches a repo-relative path. Supports `*`
// (any chars except `/`), `**` (any chars incl `/`), and a leading `**/`.
// Anchored full-string match. Intentionally small — not a full globstar impl.
//
// NOTE: this is NO LONGER how paths are matched — pathMatchesGlob below is a
// linear matcher with no regex engine. This remains for callers that need a
// RegExp (and for the SQL-predicate shapes), and throws on a glob complex enough
// to be dangerous rather than returning a regex that can hang the process.
export function globToRegExp(glob) {
  if (typeof glob !== 'string' || glob.length > MAX_GLOB_LEN) {
    throw new Error(`glob too long (max ${MAX_GLOB_LEN})`);
  }
  if ((glob.match(/\*/g) || []).length > MAX_GLOB_WILDCARDS * 2) {
    throw new Error(`glob has too many wildcards (max ${MAX_GLOB_WILDCARDS})`);
  }
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; if (glob[i + 1] === '/') i++; }
      else re += '[^/]*';
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return new RegExp('^' + re + '$');
}

/**
 * Match ONE path segment against ONE glob segment. `*` matches any run of
 * characters inside the segment; everything else is literal.
 *
 * Classic two-pointer wildcard match with a single backtrack point — correct
 * because there is only ONE kind of wildcard at this level, and O(seg x pat)
 * worst case with no regex engine to backtrack.
 */
function matchSegment(seg, pat) {
  let s = 0;
  let p = 0;
  let starP = -1;
  let starS = 0;
  while (s < seg.length) {
    if (p < pat.length && pat[p] !== '*' && pat[p] === seg[s]) { p += 1; s += 1; continue; }
    if (p < pat.length && pat[p] === '*') { starP = p; starS = s; p += 1; continue; }
    if (starP >= 0) { starS += 1; s = starS; p = starP + 1; continue; }
    return false;
  }
  while (p < pat.length && pat[p] === '*') p += 1;
  return p === pat.length;
}

/**
 * Match a repo-relative path against a glob, in LINEAR time.
 *
 * WHY NOT THE REGEX ABOVE. `globToRegExp` turns every `**` into `.*`, and a
 * regex with several `.*` separated by literals backtracks catastrophically on a
 * near-miss. Measured 2026-09-02 in a pre-release security review: a 31-char glob
 * took 300ms, 34 took 2.7s, 37 took 25.9s — exponential, so ~45 chars is hours.
 * Globs arrive from platform suppression rules, which are shipped to every CLI
 * run, and from a repo's own `.shadowspanignore`. A scanner that can be wedged by
 * one line of config is a denial of service on the customer's pipeline.
 *
 * Matching is done in two nested two-pointer passes — segments here, characters
 * in matchSegment — so each level has exactly ONE kind of wildcard and one
 * backtrack point. A single flat pass is NOT enough: `**\/*.test.js` has two
 * adjacent wildcards, and the second overwrites the first's backtrack point, so
 * `src/a.test.js` stops matching. (Caught by the existing contract test, which is
 * why it is worth keeping.)
 *
 * Semantics are unchanged from the regex: `*` matches within one segment, `**`
 * matches zero or more whole segments, `?` and the rest are literal.
 */
export function pathMatchesGlob(path, glob) {
  if (!path || !glob) return false;

  const P = path.split('/');
  const G = glob.split('/');

  let i = 0;      // path segment
  let j = 0;      // glob segment
  let starJ = -1; // glob index of the most recent `**`
  let starI = 0;  // path index when we took it

  while (i < P.length) {
    if (j < G.length && G[j] === '**') { starJ = j; starI = i; j += 1; continue; }
    if (j < G.length && matchSegment(P[i], G[j])) { i += 1; j += 1; continue; }
    if (starJ >= 0) { starI += 1; i = starI; j = starJ + 1; continue; }
    return false;
  }

  // A trailing `**` may match zero remaining segments.
  while (j < G.length && G[j] === '**') j += 1;
  return j === G.length;
}

/**
 * Does a single rule suppress this finding? Pure boolean — used by the
 * suppressed-view filter, the "preview what this rule would hide" path, and
 * tests. Scope + expiry + the MALWARE exclusion are all enforced here.
 */
export function findingMatchesRule(finding, rule, now = new Date()) {
  if (!finding || !rule) return false;
  if (finding.type === 'MALWARE') return false; // never suppressible
  if (!isRuleActive(rule, now)) return false;
  if (rule.scope === 'REPO' && finding.repositoryId !== rule.repositoryId) return false;

  const v = rule.value;
  switch (rule.matchType) {
    case 'RULE_ID':      return finding.ruleId === v;
    case 'PACKAGE':      return (finding.packageName || '').toLowerCase() === String(v || '').toLowerCase();
    case 'ECOSYSTEM':    return (finding.packageEcosystem || '').toLowerCase() === String(v || '').toLowerCase();
    case 'CWE':          return finding.cwe === v;
    case 'FINDING_TYPE': return finding.type === v;
    case 'PATH_GLOB':    return pathMatchesGlob(finding.file, v);
    default:             return false;
  }
}

/** Is this finding suppressed by ANY active rule in the set? */
export function isSuppressed(finding, rules, now = new Date()) {
  return Array.isArray(rules) && rules.some((r) => findingMatchesRule(finding, r, now));
}

// Convert one rule's match into a Prisma predicate object (the row-shape it
// matches). Returns null for rules a SQL predicate can't express precisely
// (those fall back to app-side findingMatchesRule). PATH_GLOB maps simple
// prefix/suffix/substring globs to startsWith/endsWith/contains.
function ruleToFieldPredicate(rule) {
  const v = rule.value;
  switch (rule.matchType) {
    case 'RULE_ID':      return { ruleId: v };
    case 'PACKAGE':      return { packageName: { equals: v, mode: 'insensitive' } };
    case 'ECOSYSTEM':    return { packageEcosystem: { equals: v, mode: 'insensitive' } };
    case 'CWE':          return { cwe: v };
    case 'FINDING_TYPE': return { type: v };
    case 'PATH_GLOB': {
      const g = String(v || '');
      // Map the common shapes to SQL; anything else falls back to app-side.
      //   `dir/**`        → startsWith `dir/`
      //   `**/*.ext`      → endsWith `.ext`   (any file with that extension)
      //   `**/literal`    → endsWith `literal`
      //   no `*` at all   → exact path
      let m;
      if ((m = g.match(/^([^*]+\/)\*\*$/))) return { file: { startsWith: m[1] } };
      if ((m = g.match(/^\*\*\/\*(\.[^*/]+)$/))) return { file: { endsWith: m[1] } };
      if ((m = g.match(/^\*\*\/?([^*]+)$/))) return { file: { endsWith: m[1] } };
      if (!g.includes('*')) return { file: g };
      return null; // complex glob → app-side fallback
    }
    default: return null;
  }
}

/**
 * Build a Prisma predicate that matches rows suppressed by the given rules,
 * for use as `where.NOT` (so suppressed rows are excluded) or directly (the
 * suppressed view). Only EXPRESSIBLE rules are included — callers should also
 * keep the rule list to app-side filter the residue (complex globs).
 *
 * The returned predicate is wrapped so MALWARE is NEVER matched:
 *   { AND: [ { type: { not: 'MALWARE' } }, { OR: [...perRule] } ] }
 *
 * Returns null when no rule yields an expressible predicate.
 */
export function buildSuppressionWhere(rules, now = new Date()) {
  if (!Array.isArray(rules) || rules.length === 0) return null;
  const perRule = [];
  for (const rule of rules) {
    if (!isRuleActive(rule, now)) continue;
    const field = ruleToFieldPredicate(rule);
    if (!field) continue;
    perRule.push(rule.scope === 'REPO'
      ? { AND: [{ repositoryId: rule.repositoryId }, field] }
      : field);
  }
  if (perRule.length === 0) return null;
  return { AND: [{ type: { not: 'MALWARE' } }, { OR: perRule }] };
}
