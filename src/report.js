// Build the ingest payload and POST it to the platform. Only normalized finding
// metadata is sent — the gitleaks --redact + kernel normalizer already dropped
// secret values, and we whitelist fields here as a final guard (the secret VALUE
// must never leave the machine; the rotation rule, plan §6a).

// Whitelist of finding fields sent to the platform. Notably ABSENT: any raw
// secret value / match. evidence is forwarded but the server strips
// secret-bearing keys again defensively.
const WIRE_FIELDS = [
  'type', 'ruleId', 'ruleName', 'severity', 'file', 'line', 'column',
  'description', 'remediation', 'cveId', 'packageName', 'packageEcosystem',
  'packageVersion', 'fixedVersion', 'cwe', 'identityKey', 'evidence',
];

function toWire(f) {
  const out = {};
  for (const k of WIRE_FIELDS) if (f[k] !== undefined) out[k] = f[k];
  return out;
}

/**
 * @returns the request body the ingest API expects.
 */
export function buildPayload({ source, repo, commit, scanType, failOn, findings, prComment = 'none', suppressed = null }) {
  return {
    source,
    scanType,
    failOn,
    // prComment coordinates who posts PR feedback so we never double-post:
    //   'client'   — the CLI/Action is posting from the runner (--comment-pr / token path)
    //   'platform' — ask the platform to decorate via the connected SCM App (Check Run)
    //   'none'     — not in a PR context; no decoration
    prComment,
    repo: {
      provider: repo.provider,
      owner: repo.owner,
      name: repo.name,
      url: repo.url,
      defaultBranch: repo.defaultBranch,
    },
    commit,
    // What .shadowspanignore removed BEFORE reporting, with per-rule counts. Sent so the platform
    // can show "142 findings suppressed by `**`" instead of silently showing a clean scan — the
    // repo file is a developer convenience, but it must not be an invisible one.
    suppressed: suppressed && suppressed.count > 0
      ? { count: suppressed.count, rules: (suppressed.rules || []).slice(0, 50) }
      : null,
    findings: findings.map(toWire),
  };
}

// DAST findings are target-scoped, not repo-scoped — a distinct wire whitelist
// (targetUrl present; no file/line/package fields, which are always null here).
const DAST_WIRE_FIELDS = [
  'type', 'ruleId', 'ruleName', 'severity', 'targetUrl', 'description',
  'remediation', 'cveId', 'cwe', 'identityKey', 'evidence',
];

function toDastWire(f) {
  const out = {};
  for (const k of DAST_WIRE_FIELDS) if (f[k] !== undefined) out[k] = f[k];
  return out;
}

/**
 * Build the DAST ingest body. The platform authorizes by `targetUrl` (it must
 * map to a domain-verified, ACTIVE AppSecDastTarget for the key's org) — the URL
 * is matched, never fetched server-side.
 * @returns the request body /api/v1/appsec/dast-scans expects.
 */
export function buildDastPayload({ source, targetUrl, scanType, failOn, findings }) {
  return {
    source,
    targetUrl,
    scanType,
    failOn,
    findings: findings.map(toDastWire),
  };
}

/**
 * POST DAST findings to the locked-down DAST ingest endpoint. Same never-throw
 * contract as reportScan — report failure never changes the local gate result.
 */
export async function reportDastScan({ apiUrl, apiKey, payload, timeoutMs = 30000 }) {
  const url = `${apiUrl}/api/v1/appsec/dast-scans`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'shadow-span-cli',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON */ }
    return { ok: res.ok, status: res.status, body };
  } catch (err) {
    return { ok: false, status: 0, body: { error: err.message } };
  }
}

/**
 * POST the payload. Returns { ok, status, body }. Never throws on HTTP error —
 * the caller decides whether a report failure should affect the exit code
 * (it does not: gating is local).
 */
export async function reportScan({ apiUrl, apiKey, payload, timeoutMs = 30000 }) {
  const url = `${apiUrl}/api/v1/appsec/scans`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'shadow-span-cli',
      },
      body: JSON.stringify(payload),
      // Do NOT follow redirects. Pointing --api-url at the marketing host rather
      // than the app host (shadowspan.com vs app.shadowspan.com) returns a 301,
      // and following it destroys the request in two ways at once: `fetch` strips
      // the Authorization header across origins, and a 301 rewrites POST to GET.
      // The user saw "HTTP 405: unknown error" — which says nothing about the
      // actual mistake. Verified against dev 2026-09-02.
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status >= 300 && res.status < 400) {
      const to = res.headers.get('location') || '';
      const host = (() => { try { return new URL(to, url).origin; } catch { return to; } })();
      return { ok: false, status: res.status, body: { error:
        `${apiUrl} redirects to ${host}. Point --api-url (or SHADOWSPAN_API_URL) at ${host} — `
        + 'credentials are not carried across a redirect, so the scan would be rejected.' } };
    }
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON */ }
    return { ok: res.ok, status: res.status, body };
  } catch (err) {
    return { ok: false, status: 0, body: { error: err.message } };
  }
}
