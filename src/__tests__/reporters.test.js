import { describe, it, expect } from 'vitest';
import { buildSummary, buildInlineComments, buildReviewComments, MARKER } from '../reporters/shared.js';
import { detectProvider, resolveContext } from '../reporters/index.js';
import { contextFromEnv as ghCtx } from '../reporters/github.js';
import { contextFromEnv as glCtx, inlinePosition } from '../reporters/gitlab.js';
import { contextFromEnv as bbCtx, buildAnnotations } from '../reporters/bitbucket.js';

const gate = (o = {}) => ({ failOn: 'high', blocked: true, blockingCount: 2, bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0 }, ...o });
const finding = (o = {}) => ({ type: 'SAST', ruleId: 'r', ruleName: 'Eval injection', severity: 'HIGH', file: 'src/a.js', line: 12, description: 'eval bad', cwe: 'CWE-95', ...o });

describe('shared builders', () => {
  it('summary carries the idempotency marker + a table', () => {
    const s = buildSummary({ findings: [finding()], gate: gate() });
    expect(s).toContain(MARKER);
    expect(s).toContain('src/a.js:12');
    expect(s).toMatch(/Gate failed/);
  });
  it('inline comments anchor to file+line; review-comments adapt to GitHub shape', () => {
    const inline = buildInlineComments({ findings: [finding()] });
    expect(inline[0]).toMatchObject({ file: 'src/a.js', line: 12 });
    const review = buildReviewComments({ findings: [finding()] });
    expect(review[0]).toMatchObject({ path: 'src/a.js', line: 12, side: 'RIGHT' });
  });
});

describe('detectProvider', () => {
  it('maps CI env markers', () => {
    expect(detectProvider({ GITHUB_ACTIONS: 'true' })).toBe('github');
    expect(detectProvider({ GITLAB_CI: 'true' })).toBe('gitlab');
    expect(detectProvider({ BITBUCKET_BUILD_NUMBER: '42' })).toBe('bitbucket');
    expect(detectProvider({})).toBeNull();
  });
});

describe('github.contextFromEnv', () => {
  it('builds PR context from a GitHub Actions PR env', () => {
    const c = ghCtx({ GITHUB_TOKEN: 't', GITHUB_REPOSITORY: 'acme/api', GITHUB_REF: 'refs/pull/7/merge', GITHUB_SHA: 'abc' });
    expect(c).toMatchObject({ provider: 'github', owner: 'acme', repo: 'api', prNumber: 7, commitSha: 'abc' });
  });
  it('null outside a PR', () => {
    expect(ghCtx({ GITHUB_TOKEN: 't', GITHUB_REPOSITORY: 'acme/api', GITHUB_REF: 'refs/heads/main' })).toBeNull();
  });
});

describe('gitlab.contextFromEnv + inlinePosition', () => {
  const env = {
    GITLAB_CI: 'true', SHADOWSPAN_GITLAB_TOKEN: 'glt', CI_PROJECT_ID: '99', CI_MERGE_REQUEST_IID: '4',
    CI_MERGE_REQUEST_DIFF_BASE_SHA: 'base', CI_COMMIT_SHA: 'head', CI_API_V4_URL: 'https://gl/api/v4',
  };
  it('builds MR context + diff anchors', () => {
    const c = glCtx(env);
    expect(c).toMatchObject({ provider: 'gitlab', projectId: '99', mrIid: '4', baseSha: 'base', headSha: 'head' });
  });
  it('returns null without GITLAB_CI or token/MR', () => {
    expect(glCtx({ GITLAB_CI: 'true', CI_PROJECT_ID: '99' })).toBeNull(); // no token/MR
    expect(glCtx({ ...env, GITLAB_CI: undefined })).toBeNull();
  });
  it('inlinePosition has the required Discussions-API shape', () => {
    const c = glCtx(env);
    const pos = inlinePosition(c, 'src/a.js', 12);
    expect(pos).toMatchObject({ position_type: 'text', base_sha: 'base', start_sha: 'base', head_sha: 'head', new_path: 'src/a.js', new_line: 12 });
  });
});

describe('bitbucket.contextFromEnv + buildAnnotations', () => {
  it('builds context from Pipelines env', () => {
    const c = bbCtx({ BITBUCKET_BUILD_NUMBER: '5', SHADOWSPAN_BITBUCKET_TOKEN: 'bt', BITBUCKET_WORKSPACE: 'acme', BITBUCKET_REPO_SLUG: 'api', BITBUCKET_COMMIT: 'sha1', BITBUCKET_PR_ID: '3' });
    expect(c).toMatchObject({ provider: 'bitbucket', workspace: 'acme', repo: 'api', commit: 'sha1', prId: '3' });
  });
  it('null without token', () => {
    expect(bbCtx({ BITBUCKET_BUILD_NUMBER: '5', BITBUCKET_WORKSPACE: 'a', BITBUCKET_REPO_SLUG: 'b', BITBUCKET_COMMIT: 'c' })).toBeNull();
  });
  it('annotations map to Code Insights shape', () => {
    const ann = buildAnnotations([finding()], () => 'HIGH');
    expect(ann[0]).toMatchObject({ annotation_type: 'VULNERABILITY', path: 'src/a.js', line: 12, severity: 'HIGH' });
    expect(ann[0].summary).not.toMatch(/[*_`#]/); // markdown stripped
  });
});

describe('resolveContext', () => {
  it('returns null when detected but no usable context', () => {
    expect(resolveContext({ GITLAB_CI: 'true' })).toBeNull();
  });
  it('resolves a full github context', () => {
    const r = resolveContext({ GITHUB_ACTIONS: 'true', GITHUB_TOKEN: 't', GITHUB_REPOSITORY: 'a/b', GITHUB_REF: 'refs/pull/1/merge' });
    expect(r.provider).toBe('github');
    expect(r.ctx.owner).toBe('a');
  });
});
