// SARIF 2.1.0 emitter. Upload via github/codeql-action/upload-sarif → findings
// render in the repo's Security ▸ Code scanning tab + inline PR annotations,
// with NO PR token required. Also consumed by other SARIF-aware tools.

const LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', UNKNOWN: 'note' };

export function toSarif(findings = [], { version = '0.1.0', toolUri = 'https://shadowspan.com' } = {}) {
  // Deduplicate rule metadata by ruleId for the tool.driver.rules catalog.
  const ruleMap = new Map();
  for (const f of findings) {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleName || f.ruleId,
        shortDescription: { text: (f.ruleName || f.ruleId).slice(0, 200) },
        ...(f.cwe ? { properties: { tags: [f.cwe, f.type] } } : { properties: { tags: [f.type] } }),
      });
    }
  }

  const results = findings.map((f) => ({
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
    properties: {
      severity: f.severity,
      type: f.type,
      ...(f.packageName ? { package: f.packageName, fixedVersion: f.fixedVersion } : {}),
    },
  }));

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
