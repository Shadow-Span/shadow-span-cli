// GitHub reporter — PR summary (upsert by MARKER) + inline review comments at
// file:line via the PR Review API. Uses the workflow GITHUB_TOKEN.

import { MARKER, buildSummary, buildReviewComments } from './shared.js';

export function contextFromEnv(env = process.env) {
  const token = env.SHADOWSPAN_GITHUB_TOKEN || env.GITHUB_TOKEN || null;
  const [owner, repo] = (env.GITHUB_REPOSITORY || '').split('/');
  const commitSha = env.GITHUB_SHA || null;
  let prNumber = null;
  const m = (env.GITHUB_REF || '').match(/^refs\/pull\/(\d+)\//);
  if (m) prNumber = Number(m[1]);
  if (!prNumber && env.SHADOWSPAN_PR_NUMBER) prNumber = Number(env.SHADOWSPAN_PR_NUMBER);
  if (!token || !owner || !repo || !prNumber) return null;
  return { provider: 'github', token, owner, repo, prNumber, commitSha, apiBase: env.GITHUB_API_URL || 'https://api.github.com' };
}

function api(token, apiBase) {
  return async (method, path, body) => {
    const res = await fetch(`${apiBase}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
        'User-Agent': 'shadow-span-cli',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    let json = null;
    try { json = await res.json(); } catch { /* empty */ }
    return { ok: res.ok, status: res.status, json };
  };
}

export async function post({ scope, ctx, findings, gate, reportUrl, log = () => {} }) {
  const { token, owner, repo, prNumber, commitSha, apiBase } = ctx;
  const call = api(token, apiBase);
  const summary = buildSummary({ findings, gate, reportUrl, scope });
  const reviewComments = buildReviewComments({ findings });
  const result = { provider: 'github', summary: null, review: null };

  try {
    const list = await call('GET', `/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100`);
    const prior = Array.isArray(list.json) ? list.json.find((c) => c.body?.includes(MARKER)) : null;
    if (prior) {
      const r = await call('PATCH', `/repos/${owner}/${repo}/issues/comments/${prior.id}`, { body: summary });
      result.summary = r.ok ? 'updated' : `error ${r.status}`;
    } else {
      const r = await call('POST', `/repos/${owner}/${repo}/issues/${prNumber}/comments`, { body: summary });
      result.summary = r.ok ? 'created' : `error ${r.status}`;
    }
  } catch (e) { result.summary = `exception ${e.message}`; }

  if (reviewComments.length && commitSha) {
    try {
      const r = await call('POST', `/repos/${owner}/${repo}/pulls/${prNumber}/reviews`, {
        commit_id: commitSha, event: 'COMMENT', comments: reviewComments,
      });
      result.review = r.ok ? `posted ${reviewComments.length}` : `error ${r.status} (likely off-diff lines; summary still posted)`;
    } catch (e) { result.review = `exception ${e.message}`; }
  }
  log(`[github] summary=${result.summary} review=${result.review || 'n/a'}`);
  return result;
}
