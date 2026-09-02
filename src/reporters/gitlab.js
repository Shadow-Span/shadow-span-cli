// GitLab reporter — MR summary note (upsert by MARKER) + inline discussions
// anchored to file:line via the Discussions API `position`. Token from a Project/
// Group Access Token (CI_JOB_TOKEN usually can't post notes) — SHADOWSPAN_GITLAB_TOKEN.

import { MARKER, buildSummary, buildInlineComments } from './shared.js';

export function contextFromEnv(env = process.env) {
  if (!env.GITLAB_CI) return null;
  const token = env.SHADOWSPAN_GITLAB_TOKEN || env.CI_JOB_TOKEN || null;
  const projectId = env.CI_PROJECT_ID || null;
  const mrIid = env.CI_MERGE_REQUEST_IID || null;
  if (!token || !projectId || !mrIid) return null;
  return {
    provider: 'gitlab',
    token, projectId, mrIid,
    apiBase: env.CI_API_V4_URL || 'https://gitlab.com/api/v4', // gitleaks:allow — env var NAME, not a secret
    // Diff anchors required by the Discussions API for inline placement.
    baseSha: env.CI_MERGE_REQUEST_DIFF_BASE_SHA || null,
    headSha: env.CI_MERGE_REQUEST_SOURCE_BRANCH_SHA || env.CI_COMMIT_SHA || null,
    startSha: env.CI_MERGE_REQUEST_DIFF_BASE_SHA || null,
    usingJobToken: !env.SHADOWSPAN_GITLAB_TOKEN && !!env.CI_JOB_TOKEN,
  };
}

function api(token, apiBase) {
  return async (method, path, body) => {
    const res = await fetch(`${apiBase}${path}`, {
      method,
      headers: { 'PRIVATE-TOKEN': token, 'Content-Type': 'application/json', 'User-Agent': 'shadow-span-cli' },
      body: body ? JSON.stringify(body) : undefined,
    });
    let json = null;
    try { json = await res.json(); } catch { /* empty */ }
    return { ok: res.ok, status: res.status, json };
  };
}

/** Build the Discussions API position object for an inline comment. */
export function inlinePosition(ctx, file, line) {
  return {
    position_type: 'text',
    base_sha: ctx.baseSha,
    start_sha: ctx.startSha,
    head_sha: ctx.headSha,
    new_path: file,
    new_line: line,
  };
}

export async function post({ scope, ctx, findings, gate, reportUrl, log = () => {} }) {
  const { token, projectId, mrIid, apiBase, headSha } = ctx;
  const call = api(token, apiBase);
  const base = `/projects/${encodeURIComponent(projectId)}/merge_requests/${mrIid}`;
  const summary = buildSummary({ findings, gate, reportUrl, scope });
  const result = { provider: 'gitlab', summary: null, inline: null };

  // Summary note — upsert by MARKER.
  try {
    const list = await call('GET', `${base}/notes?per_page=100`);
    const prior = Array.isArray(list.json) ? list.json.find((n) => n.body?.includes(MARKER)) : null;
    if (prior) {
      const r = await call('PUT', `${base}/notes/${prior.id}`, { body: summary });
      result.summary = r.ok ? 'updated' : `error ${r.status}`;
    } else {
      const r = await call('POST', `${base}/notes`, { body: summary });
      result.summary = r.ok ? 'created' : `error ${r.status}`;
    }
  } catch (e) { result.summary = `exception ${e.message}`; }

  // Inline discussions — only when we have the diff anchors. Each is best-effort;
  // an off-diff line 400s that one comment, not the whole run.
  const inline = buildInlineComments({ findings });
  if (inline.length && headSha && ctx.baseSha) {
    let posted = 0, failed = 0;
    for (const c of inline) {
      try {
        const r = await call('POST', `${base}/discussions`, { body: c.body, position: inlinePosition(ctx, c.file, c.line) });
        r.ok ? posted++ : failed++;
      } catch { failed++; }
    }
    result.inline = `posted ${posted}${failed ? `, ${failed} off-diff/failed` : ''}`;
  } else if (inline.length) {
    result.inline = 'skipped (no MR diff anchors)';
  }
  log(`[gitlab] summary=${result.summary} inline=${result.inline || 'n/a'}`);
  return result;
}
