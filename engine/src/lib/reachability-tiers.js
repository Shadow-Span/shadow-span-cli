// The reachability VOCABULARY — one definition, shared by the scanner that writes tiers and the
// web app that filters, sorts and labels them.
//
// It lived in three places (the scanner, the findings API, the export API) and drifted: SAST
// shipped call-graph reachability in #958 and the API's valid-values list kept describing SCA-only
// tiers for months, so a filter the UI offered returned nothing. A vocabulary duplicated across a
// producer and two consumers is a vocabulary that will disagree.
//
// TWO ANALYSES, TWO QUESTIONS. They deliberately do NOT share a scale:
//   SCA  — "does first-party source reach this dependency, and how precisely can we say so?"
//   SAST — "is there a static call path from a program entrypoint to this sink?"
// The one thing they share is the sort order below, because a triage queue is a single list.

/**
 * SCA tiers, STRONGEST FIRST. Written by services/appsec/src/sca-reachability.js.
 *
 * Read the pair (tier, dependencyDepth) together: `NOT_IMPORTED` is only ever emitted for a DIRECT
 * dependency, and the same absence on a TRANSITIVE one is reported as UNKNOWN because it is
 * expected and proves nothing.
 */
export const SCA_TIERS = [
  'VULNERABLE_SYMBOL_CALLED',
  'VULNERABLE_PATH_IMPORTED',
  'IMPORTED',
  'TEST_ONLY',
  'NOT_IMPORTED',
  'UNKNOWN',
];

/** SAST tiers. Written by services/appsec/src/sast-reachability.js. */
export const SAST_TIERS = ['REACHABLE', 'UNREACHABLE', 'UNKNOWN'];

/**
 * Pre-2026-08 SCA values, still present on rows not yet re-scanned.
 *
 * They are kept ONLY so an existing row renders and filters instead of falling through to a blank
 * cell. Two of them were never reachability answers at all — DIRECT/TRANSITIVE are dependency
 * DEPTH, which now has its own column. Nothing writes these any more; they disappear as each
 * repository is re-scanned.
 */
export const LEGACY_SCA_TIERS = ['REACHABLE', 'DIRECT', 'TRANSITIVE'];

/** Everything a `reachability` column may legitimately hold — the filter allowlist. */
export const ALL_REACHABILITY = [...new Set([...SCA_TIERS, ...SAST_TIERS, ...LEGACY_SCA_TIERS])];

/** DIRECT vs TRANSITIVE — a separate column and a separate question. */
export const DEPENDENCY_DEPTHS = ['DIRECT', 'TRANSITIVE', 'UNKNOWN'];

/**
 * Triage sort order, most urgent first — Prisma sorts strings alphabetically, so this is applied
 * in JS after the page is fetched.
 *
 * UNKNOWN deliberately outranks NOT_IMPORTED and UNREACHABLE: "we could not determine this" must
 * surface ABOVE "we determined it is not used", or the queue quietly buries everything the
 * analysis failed on.
 */
export const REACH_RANK = {
  VULNERABLE_SYMBOL_CALLED: 0,
  VULNERABLE_PATH_IMPORTED: 1,
  REACHABLE: 2, // SAST call-graph, and legacy SCA rows
  IMPORTED: 3,
  DIRECT: 4, // legacy
  TEST_ONLY: 5,
  TRANSITIVE: 6, // legacy
  UNKNOWN: 7,
  NOT_IMPORTED: 8,
  UNREACHABLE: 9,
};

/** Rank for sorting; an unrecognised or absent tier sorts last but before nothing. */
export function reachRank(tier) {
  return REACH_RANK[tier] ?? REACH_RANK.UNKNOWN;
}

/**
 * The tiers a given finding type can actually produce — the UI must not offer a filter that can
 * only ever return zero rows.
 */
export const TIERS_BY_TYPE = {
  SCA: SCA_TIERS,
  SBOM_VULN: SCA_TIERS,
  CONTAINER: SCA_TIERS,
  SAST: SAST_TIERS,
};

/**
 * Tiers that mean "this analysis found no path / no usage", for the Hide-unreachable toggle.
 *
 * NOT a general "safe to hide" list. UNKNOWN is excluded by design — it means the analysis could
 * not answer, and hiding it would delete unexamined findings from the triage queue. MALWARE is
 * excluded at the query level by every caller: a malicious package is dangerous whether or not
 * anything imports it.
 */
export const HIDEABLE_TIERS = ['UNREACHABLE', 'NOT_IMPORTED'];
