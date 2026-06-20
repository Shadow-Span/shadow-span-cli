// CI/pre-commit gate evaluator — pure, no I/O. Given a set of normalized
// findings and a fail-on threshold, decide whether the build/commit should be
// blocked. Shared by the CLI (exit-code gating) and the ingest API (the `gate`
// field in the scan response). One definition so the local CLI and the
// platform never disagree on what "fail-on: high" means.

// Severity ordering — higher rank = more severe. Mirrors the FindingSeverity
// enum + the SEVERITY_RANK used in the Shadow Span platform AppSec routes (CRITICAL first).
export const SEVERITY_ORDER = Object.freeze(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const RANK = Object.freeze(
  SEVERITY_ORDER.reduce((m, sev, i) => { m[sev] = i; return m; }, {})
);

// fail-on threshold → minimum severity that blocks. 'none' never blocks.
export const FAIL_ON_LEVELS = Object.freeze(['none', 'low', 'medium', 'high', 'critical']);

function normSeverity(s) {
  const up = String(s || 'UNKNOWN').toUpperCase();
  return RANK[up] === undefined ? 'UNKNOWN' : up;
}

/**
 * @param {Array<{severity?: string, status?: string}>} findings  normalized findings
 * @param {object} [opts]
 * @param {string} [opts.failOn='high']   none|low|medium|high|critical
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

  // 'none' → threshold above CRITICAL so nothing ever meets it.
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
