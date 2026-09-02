// Derive repo identity (provider/owner/name) + commit context from the local
// git checkout, so a report ties to the right SourceRepository on the platform.
// Pure parser (parseRemoteUrl) is unit-tested; the git calls are best-effort and
// degrade to the directory name when there's no remote (still a valid scan).

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';

const execFileAsync = promisify(execFile);

/**
 * Parse owner/name/provider from a git remote URL.
 * Handles: git@github.com:owner/name.git, https://github.com/owner/name(.git),
 * ssh://git@host/owner/name, https://gitlab.com/group/sub/name.
 * @returns {{provider:string, owner:string, name:string}|null}
 */
export function parseRemoteUrl(url) {
  if (!url || typeof url !== 'string') return null;
  let host = '';
  let pathPart = '';

  const scp = url.match(/^[\w.-]+@([\w.-]+):(.+)$/); // scp-like: git@host:owner/name.git
  if (scp) {
    host = scp[1];
    pathPart = scp[2];
  } else {
    try {
      const u = new URL(url);
      host = u.hostname;
      pathPart = u.pathname.replace(/^\/+/, '');
    } catch {
      return null;
    }
  }

  pathPart = pathPart.replace(/\.git$/, '').replace(/\/+$/, '');
  const segs = pathPart.split('/').filter(Boolean);
  if (segs.length < 2) return null;

  const name = segs[segs.length - 1];
  const owner = segs.slice(0, -1).join('/'); // GitLab subgroups → owner = group/sub

  const provider = /github/i.test(host) ? 'GITHUB'
    : /gitlab/i.test(host) ? 'GITLAB'
    : /bitbucket/i.test(host) ? 'BITBUCKET'
    : /(dev\.azure|visualstudio)/i.test(host) ? 'AZURE_DEVOPS'
    : 'GITHUB';

  return { provider, owner, name };
}

async function git(repoPath, args) {
  try {
    const { stdout } = await execFileAsync('git', ['-C', repoPath, ...args], { timeout: 10000 });
    return stdout.trim();
  } catch {
    return null;
  }
}


/**
 * Files changed on this branch relative to `baseRef` — the set a PR gate should judge.
 *
 * THREE-DOT (`base...HEAD`) on purpose: it diffs against the MERGE BASE, so the answer is "what
 * this branch changed", not "how this branch differs from the tip of main right now". With two
 * dots, every commit landing on main while a PR is open would start counting as that PR's work
 * and could fail its gate for someone else's finding.
 *
 * Returns null — not an empty Set — when the base cannot be resolved (shallow clone, unknown ref,
 * no git). Null means "unknown", and the caller must fall back to gating on everything; an empty
 * Set would mean "this PR changed nothing" and would silently pass a gate that never ran.
 *
 * @param {string} repoPath
 * @param {string} baseRef  e.g. 'origin/main' or a SHA
 * @returns {Promise<Set<string>|null>} repo-relative paths
 */
export async function changedFiles(repoPath, baseRef) {
  if (!baseRef) return null;
  // Verify the ref resolves before diffing, so a bad ref is "unknown" rather than an empty diff.
  const resolved = await git(repoPath, ['rev-parse', '--verify', `${baseRef}^{commit}`]);
  if (!resolved) return null;
  const out = await git(repoPath, ['diff', '--name-only', `${baseRef}...HEAD`]);
  if (out === null || out === undefined) return null;
  const files = out.split('\n').map((l) => l.trim()).filter(Boolean);
  return new Set(files);
}

/**
 * Collect repo + commit context for a checkout. CI env vars override local git
 * (GitHub Actions sets GITHUB_REPOSITORY / GITHUB_SHA / GITHUB_REF).
 */
export async function collectGitInfo(repoPath) {
  const remote = await git(repoPath, ['remote', 'get-url', 'origin']);
  let repo = parseRemoteUrl(remote);

  // GitHub Actions context wins when present (authoritative for the run).
  if (process.env.GITHUB_REPOSITORY) {
    const [owner, name] = process.env.GITHUB_REPOSITORY.split('/');
    if (owner && name) repo = { provider: 'GITHUB', owner, name };
  }

  if (!repo) {
    // No remote — fall back to the directory name so the scan still records.
    const name = path.basename(path.resolve(repoPath)) || 'repo';
    repo = { provider: 'LOCAL', owner: 'local', name, url: `local://${path.resolve(repoPath)}` };
  }
  if (!repo.url) {
    repo.url = repo.provider === 'GITHUB'
      ? `https://github.com/${repo.owner}/${repo.name}`
      : `local://${path.resolve(repoPath)}`;
  }

  const branch = process.env.GITHUB_REF_NAME
    || (await git(repoPath, ['rev-parse', '--abbrev-ref', 'HEAD']))
    || null;
  const sha = process.env.GITHUB_SHA
    || (await git(repoPath, ['rev-parse', 'HEAD']))
    || null;
  const defaultBranch = (await git(repoPath, ['symbolic-ref', '--short', 'refs/remotes/origin/HEAD']))
    ?.replace(/^origin\//, '') || 'main';

  return {
    repo: { ...repo, defaultBranch },
    commit: { sha, branch, ref: process.env.GITHUB_REF || null },
  };
}

/**
 * Infer the PR/MR base ref from CI environment variables.
 *
 * PR gating — judge a change on what it changed, report everything — only engages when the CLI
 * knows the base. On GitHub that was supplied by the Action's entrypoint; on GitLab and Bitbucket
 * NOTHING supplied it, and nothing inferred it here, so `--fail-on high` judged every finding in
 * the tree. A repo with any standing debt therefore had a permanently red pipeline on those two
 * providers from its very first run — the exact "gate that is always red gets ignored" failure the
 * feature exists to prevent, and the opposite of how the same product behaves on GitHub.
 *
 * Variables, from each vendor's own documentation:
 *   GitHub    GITHUB_BASE_REF                     target branch; set only on pull_request events
 *   GitLab    CI_MERGE_REQUEST_DIFF_BASE_SHA      the MR diff base COMMIT — preferred: it is the
 *                                                 exact merge base, needs no remote-ref lookup
 *             CI_MERGE_REQUEST_TARGET_BRANCH_NAME fallback target branch name
 *   Bitbucket BITBUCKET_PR_DESTINATION_BRANCH     destination branch; PR-triggered builds only
 *
 * Deliberately NOT used: CI_MERGE_REQUEST_TARGET_BRANCH_SHA. GitLab documents it as empty in
 * ordinary merge request pipelines (populated only in merged-results pipelines), so trusting it
 * would silently produce an unresolvable base and gate on everything — the bug this fixes.
 *
 * Returns null outside a PR/MR context (a push or a local run), where "what changed" has no
 * equivalent meaning and gating on everything is the correct behaviour.
 *
 * @param {Record<string,string|undefined>} [env]
 * @returns {{ base: string, from: string } | null}
 */
export function inferDiffBase(env = process.env) {
  const val = (k) => (typeof env[k] === 'string' && env[k].trim() ? env[k].trim() : null);

  const githubBase = val('GITHUB_BASE_REF');
  if (githubBase) return { base: `origin/${githubBase}`, from: 'GITHUB_BASE_REF' };

  const gitlabSha = val('CI_MERGE_REQUEST_DIFF_BASE_SHA');
  if (gitlabSha) return { base: gitlabSha, from: 'CI_MERGE_REQUEST_DIFF_BASE_SHA' };

  const gitlabBranch = val('CI_MERGE_REQUEST_TARGET_BRANCH_NAME');
  if (gitlabBranch) return { base: `origin/${gitlabBranch}`, from: 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME' };

  const bitbucketBranch = val('BITBUCKET_PR_DESTINATION_BRANCH');
  if (bitbucketBranch) return { base: `origin/${bitbucketBranch}`, from: 'BITBUCKET_PR_DESTINATION_BRANCH' };

  return null;
}
