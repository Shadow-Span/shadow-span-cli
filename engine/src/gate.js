// CI/pre-commit gate evaluator — pure, no I/O. Given a set of normalized
// findings and a fail-on threshold, decide whether the build/commit should be
// blocked. Shared by the CLI (exit-code gating) and the ingest API (the `gate`
// field in the scan response). One definition so the local CLI and the
// platform never disagree on what "fail-on: high" means.

// Severity ordering — higher rank = more severe. Mirrors the FindingSeverity
// enum + the SEVERITY_RANK used in apps/web AppSec routes (CRITICAL first).
export const SEVERITY_ORDER = Object.freeze(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const RANK = Object.freeze(
  SEVERITY_ORDER.reduce((m, sev, i) => { m[sev] = i; return m; }, {})
);

// fail-on threshold → minimum severity that blocks. 'none' never blocks;
// 'unknown' is the strictest level and blocks EVERY open finding.
//
// 'unknown' exists because the levels below it cannot express a zero-tolerance
// bar: an UNKNOWN-severity finding outranks nothing, so at `low` (the previous
// strictest) it never blocked. That is the wrong default for a scanner whose
// UNKNOWN bucket means "we could not score this yet" — an unscored advisory is
// not a safe advisory. Found dogfooding 2026-09-02: our own zero-advisory
// dependency gate could not be expressed with our own gate primitive, and the
// Go advisories it had to catch (GO-2026-5932, GO-2026-5942) carry no CVSS
// vector at all, so osv-scanner normalizes them to exactly UNKNOWN.
//
// Ordered loosest → strictest. Anything consuming this list for validation MUST
// import it rather than re-declaring the literal.
export const FAIL_ON_LEVELS = Object.freeze(['none', 'low', 'medium', 'high', 'critical', 'unknown']);

function normSeverity(s) {
  const up = String(s || 'UNKNOWN').toUpperCase();
  return RANK[up] === undefined ? 'UNKNOWN' : up;
}

/**
 * @param {Array<{severity?: string, status?: string}>} findings  normalized findings
 * @param {object} [opts]
 * @param {string} [opts.failOn='high']   none|low|medium|high|critical|unknown
 *        ('unknown' = block every open finding, including unscored ones)
 * @param {boolean} [opts.softFail=false] when true, never blocks (gate advisory only)
 * @param {boolean} [opts.openOnly=true]  only OPEN findings count toward the gate
 * @returns {{ failOn:string, blocked:boolean, blockingCount:number,
 *            total:number, bySeverity:Record<string,number> }}
 */
export function evaluateGate(findings = [], opts = {}) {
  const failOn = FAIL_ON_LEVELS.includes(String(opts.failOn).toLowerCase())
    ? String(opts.failOn).toLowerCase()
    : 'high';
  const softFail = Boolean(opts.softFail);
  const openOnly = opts.openOnly !== false;

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  let blockingCount = 0;

  // 'none' → threshold above CRITICAL so nothing ever meets it. 'unknown' →
  // RANK.UNKNOWN (0), which every normalized severity meets, so everything blocks.
  const threshold = failOn === 'none' ? Infinity : RANK[failOn.toUpperCase()];

  for (const f of findings) {
    if (openOnly && f.status && f.status !== 'OPEN') continue;
    const sev = normSeverity(f.severity);
    bySeverity[sev] += 1;
    if (RANK[sev] >= threshold) blockingCount += 1;
  }

  return {
    failOn,
    blocked: !softFail && blockingCount > 0,
    blockingCount,
    total: findings.length,
    bySeverity,
  };
}
