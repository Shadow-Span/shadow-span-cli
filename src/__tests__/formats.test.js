import { describe, it, expect } from 'vitest';
import { toSarif } from '../formats/sarif.js';
import { toCodeQuality } from '../formats/gitlab-codequality.js';

const findings = [
  { type: 'SAST', ruleId: 'js-eval', ruleName: 'eval injection', severity: 'CRITICAL', file: 'a.js', line: 2, column: 1, description: 'eval is bad', cwe: 'CWE-95', identityKey: 'SAST:js-eval:a.js:2' },
  { type: 'SCA', ruleId: 'GHSA-x', ruleName: 'lodash proto', severity: 'MEDIUM', file: 'package-lock.json', description: 'proto pollution', packageName: 'lodash', fixedVersion: '4.17.21', identityKey: 'SCA:GHSA-x:npm:lodash' },
  { type: 'SAST', ruleId: 'js-eval', ruleName: 'eval injection', severity: 'LOW', file: 'b.js', line: 9, identityKey: 'SAST:js-eval:b.js:9' },
];

describe('toSarif', () => {
  const sarif = toSarif(findings, { version: '9.9.9' });
  it('is well-formed SARIF 2.1.0', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('Shadow Span AppSec');
    expect(sarif.runs[0].tool.driver.version).toBe('9.9.9');
  });
  it('dedupes rules by ruleId', () => {
    const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id).sort();
    expect(ids).toEqual(['GHSA-x', 'js-eval']); // js-eval appears once despite 2 results
  });
  it('maps severity → level + anchors location + carries fingerprint', () => {
    const r = sarif.runs[0].results[0];
    expect(r.ruleId).toBe('js-eval');
    expect(r.level).toBe('error'); // CRITICAL → error
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe('a.js');
    expect(r.locations[0].physicalLocation.region.startLine).toBe(2);
    expect(r.partialFingerprints.shadowSpanIdentity).toBe('SAST:js-eval:a.js:2');
  });
  it('MEDIUM → warning, LOW → note', () => {
    expect(sarif.runs[0].results[1].level).toBe('warning');
    expect(sarif.runs[0].results[2].level).toBe('note');
  });
});

describe('toCodeQuality', () => {
  const cq = toCodeQuality(findings);
  it('maps to GitLab Code Quality shape + severities', () => {
    expect(cq).toHaveLength(3);
    expect(cq[0]).toMatchObject({ check_name: 'js-eval', severity: 'blocker', location: { path: 'a.js', lines: { begin: 2 } } });
    expect(cq[1].severity).toBe('major');  // MEDIUM
    expect(cq[2].severity).toBe('minor');  // LOW
  });
  it('fingerprints are stable + unique per finding', () => {
    const fps = cq.map((c) => c.fingerprint);
    expect(new Set(fps).size).toBe(3);
    expect(toCodeQuality(findings)[0].fingerprint).toBe(cq[0].fingerprint); // deterministic
  });
});
