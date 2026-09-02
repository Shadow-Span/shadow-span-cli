import { describe, it, expect } from 'vitest';
import { inferDiffBase } from '../git-info.js';

/**
 * PR-gate base inference across SCM providers.
 *
 * The gate judges a change on what it CHANGED and reports everything — but only when the CLI knows
 * the base. That was supplied solely by the GitHub Action's entrypoint, so the same product gated on
 * changed files under GitHub and on the WHOLE TREE under GitLab and Bitbucket, where the shipped
 * templates pass no --diff-base and nothing inferred one. On this repo that would be 335 findings at
 * `--fail-on high`: a red pipeline on a customer's first run that they cannot clear, which is
 * precisely the "gate that is always red gets ignored" outcome the feature exists to avoid.
 *
 * Variable names are asserted as the vendors document them — the other side of the interface.
 */
describe('inferDiffBase', () => {
  it('GitHub Actions: GITHUB_BASE_REF (pull_request only)', () => {
    expect(inferDiffBase({ GITHUB_BASE_REF: 'main' })).toEqual({ base: 'origin/main', from: 'GITHUB_BASE_REF' });
  });

  it('GitLab: prefers the exact merge-base SHA over the target branch name', () => {
    // CI_MERGE_REQUEST_DIFF_BASE_SHA is the real merge base and needs no remote-ref lookup, so it
    // wins when both are present.
    const both = {
      CI_MERGE_REQUEST_DIFF_BASE_SHA: 'deadbeefcafe',
      CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main',
    };
    expect(inferDiffBase(both)).toEqual({ base: 'deadbeefcafe', from: 'CI_MERGE_REQUEST_DIFF_BASE_SHA' });
  });

  it('GitLab: falls back to the target branch name', () => {
    expect(inferDiffBase({ CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'develop' }))
      .toEqual({ base: 'origin/develop', from: 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME' });
  });

  it('GitLab: ignores CI_MERGE_REQUEST_TARGET_BRANCH_SHA', () => {
    // GitLab documents it as EMPTY in ordinary merge request pipelines (populated only in
    // merged-results pipelines). Trusting it would yield an unresolvable base and silently gate on
    // everything — the bug this function fixes, reintroduced by a different route.
    expect(inferDiffBase({ CI_MERGE_REQUEST_TARGET_BRANCH_SHA: 'abc123' })).toBeNull();
  });

  it('Bitbucket Pipelines: BITBUCKET_PR_DESTINATION_BRANCH (PR builds only)', () => {
    expect(inferDiffBase({ BITBUCKET_PR_DESTINATION_BRANCH: 'main' }))
      .toEqual({ base: 'origin/main', from: 'BITBUCKET_PR_DESTINATION_BRANCH' });
  });

  it('returns null outside a PR/MR context — gating on everything is correct there', () => {
    expect(inferDiffBase({})).toBeNull();
    expect(inferDiffBase({ GITHUB_REF_NAME: 'main', CI: 'true' })).toBeNull(); // a push build
  });

  it('treats empty and whitespace-only values as absent', () => {
    // GitLab and the GitHub runner both set these keys unconditionally on non-PR events; an empty
    // string must not become the base `origin/` and resolve to nothing.
    expect(inferDiffBase({ GITHUB_BASE_REF: '' })).toBeNull();
    expect(inferDiffBase({ GITHUB_BASE_REF: '   ' })).toBeNull();
    expect(inferDiffBase({ CI_MERGE_REQUEST_DIFF_BASE_SHA: '' })).toBeNull();
    expect(inferDiffBase({ BITBUCKET_PR_DESTINATION_BRANCH: '' })).toBeNull();
  });

  it('every provider yields a base that is safe to hand to `git rev-parse`', () => {
    const cases = [
      { GITHUB_BASE_REF: 'release/2.0' },
      { CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'feature/x' },
      { BITBUCKET_PR_DESTINATION_BRANCH: 'main' },
      { CI_MERGE_REQUEST_DIFF_BASE_SHA: '0123456789abcdef0123456789abcdef01234567' },
    ];
    for (const env of cases) {
      const { base } = inferDiffBase(env);
      expect(base).toBeTruthy();
      expect(base).not.toMatch(/\s/);       // a ref with whitespace would break the diff call
      expect(base).not.toMatch(/^origin\/$/); // never a bare remote prefix
    }
  });
});
