import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, mkdir, rm, access, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { run } from '../cli.js';
import { parseRemoteUrl } from '../git-info.js';
import { buildPayload } from '../report.js';

function fakeIo() {
  const out = [], err = [];
  return { log: (m) => out.push(m), error: (m) => err.push(m), out, err };
}

describe('cli run() — dispatch + exit codes', () => {
  beforeEach(() => { delete process.env.SHADOWSPAN_API_KEY; });

  it('version → 0', async () => {
    const io = fakeIo();
    expect(await run(['version'], io)).toBe(0);
    expect(io.out.join('')).toMatch(/\d+\.\d+\.\d+/);
  });

  it('help → 0 and prints usage', async () => {
    const io = fakeIo();
    expect(await run(['help'], io)).toBe(0);
    expect(io.out.join('\n')).toMatch(/USAGE/);
  });

  it('unknown command → 2', async () => {
    const io = fakeIo();
    expect(await run(['frobnicate'], io)).toBe(2);
  });

  it('unknown flag → 2 (strict parse)', async () => {
    const io = fakeIo();
    expect(await run(['scan', '--definitely-not-a-flag'], io)).toBe(2);
  });

  it('auth without a key → 2', async () => {
    const io = fakeIo();
    expect(await run(['auth'], io)).toBe(2);
    expect(io.err.join('')).toMatch(/api-key/);
  });

  it('scan with a bad --engines value → 2', async () => {
    const io = fakeIo();
    expect(await run(['scan', '--engines', 'secret,nope'], io)).toBe(2);
    expect(io.err.join('')).toMatch(/Unknown engine/);
  });

  it('scan with an invalid --mode → 2 (before any engine runs)', async () => {
    const io = fakeIo();
    expect(await run(['scan', '--mode', 'whoops'], io)).toBe(2);
    expect(io.err.join('')).toMatch(/Invalid --mode/);
  });
});

describe('install-hook', () => {
  let dir, cwd;
  beforeEach(() => { cwd = process.cwd(); });

  it('refuses outside a git repo → 2', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'ssh-nogit-'));
    process.chdir(dir);
    const io = fakeIo();
    try {
      expect(await run(['install-hook'], io)).toBe(2);
      expect(io.err.join('')).toMatch(/no \.git/);
    } finally { process.chdir(cwd); await rm(dir, { recursive: true, force: true }); }
  });

  it('writes a local-only pre-commit hook inside a git repo', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'ssh-git-'));
    await mkdir(path.join(dir, '.git', 'hooks'), { recursive: true });
    process.chdir(dir);
    const io = fakeIo();
    try {
      expect(await run(['install-hook'], io)).toBe(0);
      const hook = path.join(dir, '.git', 'hooks', 'pre-commit');
      await access(hook); // exists
      const body = await readFile(hook, 'utf8');
      expect(body).toMatch(/--no-report/);     // local-only
      expect(body).toMatch(/--engines secret/);
      expect(body).toMatch(/SKIP_SHADOWSPAN/);  // bypass escape hatch
    } finally { process.chdir(cwd); await rm(dir, { recursive: true, force: true }); }
  });

  it('refuses to clobber an existing hook without --force', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'ssh-git2-'));
    await mkdir(path.join(dir, '.git', 'hooks'), { recursive: true });
    const hook = path.join(dir, '.git', 'hooks', 'pre-commit');
    await (await import('node:fs/promises')).writeFile(hook, '#!/bin/sh\necho existing\n');
    process.chdir(dir);
    const io = fakeIo();
    try {
      expect(await run(['install-hook'], io)).toBe(2);
      expect(await run(['install-hook', '--force'], io)).toBe(0);
    } finally { process.chdir(cwd); await rm(dir, { recursive: true, force: true }); }
  });
});

describe('parseRemoteUrl', () => {
  it('parses scp-style git@ urls', () => {
    expect(parseRemoteUrl('git@github.com:acme/payments-api.git'))
      .toEqual({ provider: 'GITHUB', owner: 'acme', name: 'payments-api' });
  });
  it('parses https github urls with .git', () => {
    expect(parseRemoteUrl('https://github.com/acme/payments-api.git'))
      .toEqual({ provider: 'GITHUB', owner: 'acme', name: 'payments-api' });
  });
  it('handles gitlab subgroups (owner = group/sub)', () => {
    expect(parseRemoteUrl('https://gitlab.com/group/sub/proj.git'))
      .toEqual({ provider: 'GITLAB', owner: 'group/sub', name: 'proj' });
  });
  it('detects azure devops', () => {
    expect(parseRemoteUrl('git@ssh.dev.azure.com:v3/org/project/repo')?.provider).toBe('AZURE_DEVOPS');
  });
  it('returns null for junk', () => {
    expect(parseRemoteUrl('not-a-url')).toBeNull();
    expect(parseRemoteUrl('')).toBeNull();
    expect(parseRemoteUrl(null)).toBeNull();
  });
});

describe('buildPayload', () => {
  const repo = { provider: 'GITHUB', owner: 'a', name: 'b', url: 'https://github.com/a/b', defaultBranch: 'main' };
  const commit = { sha: 'abc', branch: 'feat', ref: null };

  it('whitelists fields and never forwards a raw secret value', () => {
    const findings = [{
      type: 'SECRET', ruleId: 'k', ruleName: 'Key', severity: 'HIGH', identityKey: 'SECRET:x',
      file: 'a.js', line: 1, description: 'd', evidence: { rule: 'k' },
      // hostile extra fields that must NOT be forwarded:
      Secret: 'sk-live-PLAINTEXT', rawLine: 'token=sk-live-PLAINTEXT', internalNote: 'x',
    }];
    const payload = buildPayload({ source: 'cli', repo, commit, scanType: 'full', failOn: 'high', findings });
    const wire = payload.findings[0];
    expect(wire.Secret).toBeUndefined();
    expect(wire.rawLine).toBeUndefined();
    expect(wire.internalNote).toBeUndefined();
    expect(JSON.stringify(payload)).not.toContain('PLAINTEXT');
    expect(wire.identityKey).toBe('SECRET:x');
    expect(payload.repo.owner).toBe('a');
    expect(payload.commit.sha).toBe('abc');
  });
});
