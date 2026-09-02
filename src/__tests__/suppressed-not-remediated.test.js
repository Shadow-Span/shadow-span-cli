// A suppressed finding must never be reported as FIXED.
//
// THE BUG (pre-release security review, 2026-09-02). Suppressed findings were
// removed from `findings` before `buildPayload`, and the server closes every
// finding MISSING from a FULL scan's payload as `status: 'REMEDIATED'` with a
// `fixedAt` (packages/appsec-engine/src/findings.js; ingest.js passes
// `closeStale: scanType === 'full'`).
//
// So one committed `.shadowspan-suppressions.json` would have made the platform
// record a vulnerability as FIXED when it had only been accepted — silent
// corruption of the customer's security history, through a channel that also
// recorded nothing in AppSecScan.suppressedCount.
//
// The fix: suppressions gate LOCALLY but are still REPORTED. This asserts that
// contract at the payload boundary, which is where the damage was done.
import { describe, it, expect } from 'vitest';

import { buildPayload } from '../report.js';

const kept = { type: 'SCA', ruleId: 'CVE-OPEN', severity: 'HIGH', file: 'package-lock.json', identityKey: 'k1' };
const accepted = { type: 'SCA', ruleId: 'CVE-ACCEPTED', severity: 'LOW', file: 'package-lock.json', identityKey: 'k2' };
const rule = { matchType: 'RULE_ID', value: 'CVE-ACCEPTED', reason: 'no fix published', expiresOn: '2027-01-01' };

const base = {
  source: 'cli',
  repo: { provider: 'GITHUB', owner: 'acme', name: 'api', url: 'https://github.com/acme/api' },
  commit: { sha: 'a'.repeat(40), branch: 'main' },
  scanType: 'full',
  failOn: 'high',
  prComment: 'none',
};

describe('report payload — suppressed findings', () => {
  it('includes an accepted-risk finding, so a full scan cannot close it as REMEDIATED', () => {
    const p = buildPayload({
      ...base,
      findings: [kept, accepted],
      suppressed: { count: 1, rules: ['RULE_ID:CVE-ACCEPTED'] },
    });
    const ids = p.findings.map((f) => f.ruleId);
    expect(ids).toContain('CVE-ACCEPTED');
    expect(ids).toContain('CVE-OPEN');
  });

  it('records the suppression in the scan audit fields', () => {
    const p = buildPayload({
      ...base,
      findings: [kept, accepted],
      suppressed: { count: 1, rules: [{ rule: `${rule.matchType}:${rule.value}`, count: 1 }] },
    });
    expect(p.suppressed.count).toBe(1);
    // The SERVER's contract, not our string format: v1/appsec/scans keeps only
    // entries shaped `{ rule: string, count: int }` and silently drops the rest,
    // so a plain string list recorded a count with no attribution. Verified
    // against a live ingest — the column came back null.
    expect(p.suppressed.rules).toEqual([{ rule: 'RULE_ID:CVE-ACCEPTED', count: 1 }]);
  });

  it('a finding that is genuinely absent is still absent — closure still works', () => {
    // The fix must not defeat legitimate remediation: something actually fixed
    // disappears from the payload and SHOULD be closed.
    const p = buildPayload({ ...base, findings: [kept], suppressed: { count: 0, rules: [] } });
    expect(p.findings.map((f) => f.ruleId)).toEqual(['CVE-OPEN']);
  });
});

describe('cli.js — the payload is built from kept + suppressed', () => {
  // Guards the wiring that the payload-level tests above cannot see. The bug was
  // precisely that `findings` (kept only) was passed here.
  it('passes a merged list, not the gated subset', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const path = (await import('node:path')).default;
    const src = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'cli.js'), 'utf8',
    );
    expect(src).toMatch(/const reportedFindings = \[\.\.\.findings, \.\.\.suppressedFindings\.map/);
    expect(src).toMatch(/findings: reportedFindings/);
  });
});
