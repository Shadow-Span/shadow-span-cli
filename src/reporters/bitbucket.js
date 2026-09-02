// Bitbucket reporter — Code Insights report + inline annotations (the native
// in-diff surface), plus a PR summary comment when a PR id is present. Auth via a
// repo/workspace access token (SHADOWSPAN_BITBUCKET_TOKEN) or Pipelines OIDC.

import { buildSummary, buildInlineComments, SEV_ORDER } from './shared.js';

const REPORT_ID = 'shadow-span-appsec';
// Bitbucket annotation severities — no UNKNOWN; map it to LOW.
const BB_SEVERITY = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', UNKNOWN: 'LOW' };

export function contextFromEnv(env = process.env) {
  if (!env.BITBUCKET_BUILD_NUMBER) return null;
  const token = env.SHADOWSPAN_BITBUCKET_TOKEN || env.BITBUCKET_ACCESS_TOKEN || null;
  const workspace = env.BITBUCKET_WORKSPACE || null;
  const repo = env.BITBUCKET_REPO_SLUG || null;
  const commit = env.BITBUCKET_COMMIT || null;
  if (!token || !workspace || !repo || !commit) return null;
  return {
    provider: 'bitbucket',
    token, workspace, repo, commit,
    prId: env.BITBUCKET_PR_ID || null,
    apiBase: env.BITBUCKET_API_URL || 'https://api.bitbucket.org/2.0',
  };
}

function api(token, apiBase) {
  return async (method, path, body) => {
    const res = await fetch(`${apiBase}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'User-Agent': 'shadow-span-cli' },
      body: body ? JSON.stringify(body) : undefined,
    });
    let json = null;
    try { json = await res.json(); } catch { /* empty */ }
    return { ok: res.ok, status: res.status, json };
  };
}

/** Build the Code Insights annotations array from inline findings. */
export function buildAnnotations(findings, severityOf) {
  const inline = buildInlineComments({ findings, max: 1000 });
  return inline.map((c, i) => ({
    external_id: `shadow-span-${i}-${c.file}-${c.line}`,
    annotation_type: 'VULNERABILITY',
    path: c.file,
    line: c.line,
    summary: c.body.split('\n')[0].replace(/[*_`#]/g, ''),
    severity: severityOf(c) || 'LOW',
  }));
}

export async function post({ scope, ctx, findings, gate, reportUrl, log = () => {} }) {
  const { token, workspace, repo, commit, prId, apiBase } = ctx;
  const call = api(token, apiBase);
  const base = `/repositories/${workspace}/${repo}`;
  const result = { provider: 'bitbucket', report: null, annotations: null, comment: null };

  // 1. Code Insights report (PASSED/FAILED drives the PR's build status).
  try {
    const r = await call('PUT', `${base}/commit/${commit}/reports/${REPORT_ID}`, {
      title: 'Shadow Span AppSec',
      details: scope
        ? `${findings.length} finding(s) in repo · ${scope.gatedCount} in this PR's changed files · ${gate.blockingCount} at or above ${gate.failOn}`
        : `${findings.length} finding(s) · ${gate.blockingCount} at or above ${gate.failOn}`,
      report_type: 'SECURITY',
      reporter: 'Shadow Span',
      result: gate.blocked ? 'FAILED' : 'PASSED',
      ...(reportUrl ? { link: reportUrl } : {}),
      data: SEV_ORDER.filter((s) => gate.bySeverity?.[s]).map((s) => ({ title: s, type: 'NUMBER', value: gate.bySeverity[s] })),
    });
    result.report = r.ok ? (gate.blocked ? 'FAILED' : 'PASSED') : `error ${r.status}`;
  } catch (e) { result.report = `exception ${e.message}`; }

  // 2. Inline annotations (bulk). Map our finding severity onto each comment.
  const sevByLoc = new Map(findings.filter((f) => f.file && f.line).map((f) => [`${f.file}:${f.line}`, BB_SEVERITY[f.severity] || 'LOW']));
  const annotations = buildAnnotations(findings, (c) => sevByLoc.get(`${c.file}:${c.line}`));
  if (annotations.length) {
    try {
      // Bitbucket caps ~100 annotations/report; chunk.
      let posted = 0;
      for (let i = 0; i < annotations.length; i += 100) {
        const r = await call('POST', `${base}/commit/${commit}/reports/${REPORT_ID}/annotations`, annotations.slice(i, i + 100));
        if (r.ok) posted += Math.min(100, annotations.length - i);
      }
      result.annotations = `posted ${posted}`;
    } catch (e) { result.annotations = `exception ${e.message}`; }
  }

  // 3. PR summary comment (if a PR id is in context).
  if (prId) {
    try {
      const r = await call('POST', `${base}/pullrequests/${prId}/comments`, { content: { raw: buildSummary({ findings, gate, reportUrl, scope }) } });
      result.comment = r.ok ? 'posted' : `error ${r.status}`;
    } catch (e) { result.comment = `exception ${e.message}`; }
  }
  log(`[bitbucket] report=${result.report} annotations=${result.annotations || 'n/a'} comment=${result.comment || 'n/a'}`);
  return result;
}
