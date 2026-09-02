// CLI wiring for `.shadowspan-suppressions.json` — loading, validation, and the
// APPLY step that decides what gates.
//
// NO ENGINE BINARIES. The engines are mocked, so this suite needs neither
// osv-scanner nor gitleaks on PATH. That is not just convenience: these tests are
// about suppression logic, and an earlier version drove the real `runEngines`,
// which silently made the unit suite depend on a scanner being installed. It went
// unnoticed because osv-scanner was on PATH locally and in the same CI job — then
// the dependency gate moved to its own job and four tests failed with
// "Cannot scan: 1 required engine binary is unavailable".
//
// Mocking also makes the tests BETTER, not just cheaper: real findings can be fed
// in, so the apply step can be asserted on actual data instead of inferred from an
// empty repo.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Findings the fake SCA engine returns. Reassigned per test.
let ENGINE_FINDINGS = [];

vi.mock('../scan.js', async (orig) => ({
  ...(await orig()),
  runEngines: vi.fn(async () => ({ findings: ENGINE_FINDINGS, errors: [] })),
}));

// preflight proves the engine binaries exist. There are none here by design, so
// it is stubbed to pass — the real preflight has its own tests, and its job (a
// missing binary must never look like "no findings") is not what this file covers.
vi.mock('../../engine/src/index.js', async (orig) => ({
  ...(await orig()),
  preflight: vi.fn(async () => ({ ok: true, missing: [] })),
}));

const { run } = await import('../cli.js');
const { SUPPRESSION_FILENAME } = await import('../../engine/src/suppression-file.js');

// Inside the kernel's 365-day expiry ceiling, computed rather than hard-coded so
// this file does not quietly expire and start failing a year from now.
const FUTURE = new Date(Date.now() + 200 * 864e5).toISOString().slice(0, 10);

function fakeIo() {
  const out = [], err = [];
  return { log: (m) => out.push(m), error: (m) => err.push(m), out, err };
}

async function repoWith(contents) {
  const dir = await mkdtemp(path.join(tmpdir(), 'cli-supp-'));
  if (contents !== null) await writeFile(path.join(dir, SUPPRESSION_FILENAME), contents);
  return dir;
}

const finding = (over = {}) => ({
  type: 'SCA', ruleId: 'CVE-2026-1', ruleName: 'a vulnerable dep', severity: 'HIGH',
  file: 'package-lock.json', description: 'x', packageName: 'left-pad',
  identityKey: 'SCA:CVE-2026-1', ...over,
});

const rule = (over = {}) => ({
  matchType: 'RULE_ID', value: 'CVE-2026-1', reason: 'not reachable',
  expiresAt: FUTURE, upstream: 'https://example.com/1', ...over,
});
const doc = (...rules) => JSON.stringify({ suppressions: rules });

// --no-report keeps it local; --mode alert stops a blocked gate becoming exit 1,
// so exit codes here mean "config/scan error", not "findings found".
const scanArgs = (dir) => ['scan', '--engines', 'sca', '--no-report', '--mode', 'alert', dir];

beforeEach(() => { ENGINE_FINDINGS = []; });

describe('CLI — .shadowspan-suppressions.json loading + validation', () => {
  it('rejects invalid JSON with exit 2 before scanning', async () => {
    const dir = await repoWith('{ not json');
    try {
      const io = fakeIo();
      expect(await run(scanArgs(dir), io)).toBe(2);
      expect(io.err.join('\n')).toMatch(/not valid JSON/);
      expect(io.err.join('\n')).not.toMatch(/running sca/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each([
    ['missing reason', doc({ matchType: 'RULE_ID', value: 'CVE-1', expiresAt: FUTURE }), /missing "reason"/],
    ['missing expiry', doc({ matchType: 'RULE_ID', value: 'CVE-1', reason: 'because' }), /missing "expiresAt"/],
    ['breadth-unbounded matchType', doc(rule({ matchType: 'PATH_GLOB', value: '**' })), /matchType must be one of/],
  ])('rejects %s with exit 2', async (_n, body, re) => {
    const dir = await repoWith(body);
    try {
      const io = fakeIo();
      expect(await run(scanArgs(dir), io)).toBe(2);
      expect(io.err.join('\n')).toMatch(re);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('warns about an expired rule rather than failing the config', async () => {
    const dir = await repoWith(doc(rule({ expiresAt: '2020-01-01' })));
    try {
      const io = fakeIo();
      expect(await run(scanArgs(dir), io)).not.toBe(2);
      expect(io.err.join('\n')).toMatch(/expired on 2020-01-01/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('a repo with no suppression file scans normally', async () => {
    const dir = await repoWith(null);
    try {
      expect(await run(scanArgs(dir), fakeIo())).toBe(0);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});

describe('CLI — suppressions are actually applied to findings', () => {
  it('suppresses a matching finding and reports why', async () => {
    ENGINE_FINDINGS = [finding()];
    const dir = await repoWith(doc(rule()));
    try {
      const io = fakeIo();
      await run(scanArgs(dir), io);
      const err = io.err.join('\n');
      expect(err).toMatch(/1 finding\(s\) suppressed/);
      expect(err).toContain('CVE-2026-1');
      expect(err).toContain('not reachable');   // the reason is on the record
      expect(err).toContain(FUTURE);            // and so is the expiry
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('leaves a NON-matching finding to gate', async () => {
    ENGINE_FINDINGS = [finding({ ruleId: 'CVE-2026-OTHER' })];
    const dir = await repoWith(doc(rule()));
    try {
      const io = fakeIo();
      await run(scanArgs(dir), io);
      expect(io.err.join('\n')).not.toMatch(/finding\(s\) suppressed/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('an EXPIRED rule does not suppress — the finding comes back', async () => {
    ENGINE_FINDINGS = [finding()];
    const dir = await repoWith(doc(rule({ expiresAt: '2020-01-01' })));
    try {
      const io = fakeIo();
      await run(scanArgs(dir), io);
      expect(io.err.join('\n')).not.toMatch(/finding\(s\) suppressed/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('never suppresses MALWARE, even when a rule names it exactly', async () => {
    ENGINE_FINDINGS = [finding({ type: 'MALWARE', ruleId: 'MAL-2026-1', severity: 'CRITICAL' })];
    const dir = await repoWith(doc(rule({ value: 'MAL-2026-1' })));
    try {
      const io = fakeIo();
      await run(scanArgs(dir), io);
      expect(io.err.join('\n')).not.toMatch(/finding\(s\) suppressed/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('flags a rule that matches nothing, so dead entries do not accumulate', async () => {
    ENGINE_FINDINGS = [finding({ ruleId: 'CVE-2026-OTHER' })];
    const dir = await repoWith(doc(rule({ value: 'CVE-2026-NOTHING' })));
    try {
      const io = fakeIo();
      await run(scanArgs(dir), io);
      expect(io.err.join('\n')).toMatch(/matches nothing — remove it from \.shadowspan-suppressions\.json/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
