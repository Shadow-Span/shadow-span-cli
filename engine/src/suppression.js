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

// Minimal, predictable glob → matches a repo-relative path. Supports `*`
// (any chars except `/`), `**` (any chars incl `/`), and a leading `**/`.
// Anchored full-string match. Intentionally small — not a full globstar impl.
export function globToRegExp(glob) {
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

export function pathMatchesGlob(path, glob) {
  if (!path || !glob) return false;
  try { return globToRegExp(glob).test(path); } catch { return false; }
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
