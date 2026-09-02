// SARIF 2.1.0 emitter. Upload via github/codeql-action/upload-sarif → findings
// render in the repo's Security ▸ Code scanning tab + inline PR annotations,
// with NO PR token required. Also consumed by other SARIF-aware tools.

const LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', UNKNOWN: 'note' };

/**
 * @param {Array} findings              findings that still stand (these gate)
 * @param {object} [opts]
 * @param {Array<{finding:object, rule:object}>} [opts.suppressed]
 *        Findings an accepted-risk rule matched. They are emitted as results too,
 *        carrying SARIF's native `suppressions[]`, so a code-scanning upload shows
 *        them as suppressed rather than not showing them at all. Omitting them
 *        made an accepted risk indistinguishable from a finding that never
 *        existed — the reviewer of the SARIF has no way to know a decision was
 *        made, which is exactly the silent channel .shadowspanignore reporting
 *        exists to prevent.
 */
export function toSarif(findings = [], { version = '0.1.0', toolUri = 'https://shadowspan.com', suppressed = [] } = {}) {
  // Deduplicate rule metadata by ruleId for the tool.driver.rules catalog —
  // suppressed results reference rules too, so they must be catalogued as well.
  const ruleMap = new Map();
  for (const f of [...findings, ...suppressed.map((s) => s.finding)]) {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleName || f.ruleId,
        shortDescription: { text: (f.ruleName || f.ruleId).slice(0, 200) },
        ...(f.cwe ? { properties: { tags: [f.cwe, f.type] } } : { properties: { tags: [f.type] } }),
      });
    }
  }

  const toResult = (f, suppression) => ({
    ruleId: f.ruleId,
    level: LEVEL[f.severity] || 'note',
    message: { text: f.description || f.ruleName || f.ruleId },
    ...(f.file ? {
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file },
          ...(f.line ? { region: { startLine: f.line, ...(f.column ? { startColumn: f.column } : {}) } } : {}),
        },
      }],
    } : {}),
    ...(f.identityKey ? { partialFingerprints: { shadowSpanIdentity: f.identityKey } } : {}),
    // SARIF 2.1.0 §3.27.23 — a non-empty `suppressions` array marks the result
    // suppressed; GitHub code scanning renders it as such instead of an alert.
    ...(suppression ? {
      suppressions: [{
        kind: 'external',
        justification: suppression.reason || '(no reason recorded)',
        ...(suppression.expiresOn ? { properties: { expiresOn: suppression.expiresOn } } : {}),
      }],
    } : {}),
    properties: {
      severity: f.severity,
      type: f.type,
      ...(f.packageName ? { package: f.packageName, fixedVersion: f.fixedVersion } : {}),
    },
  });

  const results = [
    ...findings.map((f) => toResult(f, null)),
    ...suppressed.map(({ finding, rule }) => toResult(finding, rule)),
  ];

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Shadow Span AppSec',
          informationUri: toolUri,
          version,
          rules: [...ruleMap.values()],
        },
      },
      results,
    }],
  };
}
