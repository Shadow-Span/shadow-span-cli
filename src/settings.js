// Fetch the org's AppSec scanner settings (secret allowlist + path exclusions +
// suppression rules) so they apply to local + CI runs. The SECRET ALLOWLIST
// especially must come from here — it's value-based and runs at gitleaks time on
// this machine, so it can't be enforced server-side at ingest (the matched value
// never leaves). Path exclusions are also returned (the server enforces those at
// ingest too; applying them here keeps the LOCAL gate result consistent).
// SUPPRESSION RULES let a risk accepted in the dashboard also stop blocking CI —
// without them the same finding is green in one place and red in the other.
//
// Best-effort: any failure returns null and the scan proceeds with no org
// settings — never blocks. That direction is deliberate. Failing open on
// SUPPRESSIONS means more findings block, not fewer, so an unreachable platform
// can only ever make the gate stricter.

/** Repo identity lets the server resolve scope=REPO rules; ORG rules need no params. */
function settingsUrl(apiUrl, repo) {
  const url = new URL('/api/v1/appsec/settings', apiUrl);
  if (repo?.provider && repo?.owner && repo?.name) {
    url.searchParams.set('provider', repo.provider);
    url.searchParams.set('owner', repo.owner);
    url.searchParams.set('name', repo.name);
  }
  return url.toString();
}

/**
 * Validate a rule the SERVER sent. The platform is trusted more than a repo file,
 * but a malformed row must not become a rule that silently matches nothing (or
 * worse, everything) — the kernel would just see undefined fields.
 */
function normalizeRule(r) {
  const MATCH_TYPES = ['RULE_ID', 'PATH_GLOB', 'PACKAGE', 'ECOSYSTEM', 'CWE', 'FINDING_TYPE'];
  if (!r || !MATCH_TYPES.includes(r.matchType)) return null;
  if (typeof r.value !== 'string' || !r.value.trim()) return null;

  const expiresAt = r.expiresAt ? new Date(r.expiresAt) : null;
  if (r.expiresAt && Number.isNaN(expiresAt?.getTime())) return null;

  return {
    // Scope is forced to ORG because the SERVER already decided applicability by
    // repository. findingMatchesRule() compares rule.repositoryId against
    // finding.repositoryId, and a CLI finding has no repositoryId (that id is
    // assigned at ingest) — so leaving scope='REPO' here would make every
    // repo-scoped rule silently inert, which looks exactly like it working.
    scope: 'ORG',
    matchType: r.matchType,
    value: r.value,
    expiresAt,
    reason: typeof r.reason === 'string' && r.reason.trim() ? r.reason : '(no reason recorded)',
    origin: 'platform',
    originScope: r.scope === 'REPO' ? 'REPO' : 'ORG',
  };
}

export async function fetchAppSecSettings({ apiUrl, apiKey, repo, timeoutMs = 10000 }) {
  if (!apiUrl || !apiKey) return null;
  try {
    const res = await fetch(settingsUrl(apiUrl, repo), {
      headers: { Authorization: `Bearer ${apiKey}`, 'User-Agent': 'shadow-span-cli' },
      // See reportScan: a redirect to the app host strips Authorization, so
      // following it yields a 401 that looks like a bad key. Surfaced rather than
      // followed — this call is best-effort, and silently getting no org settings
      // because of a wrong hostname is exactly the kind of quiet wrong answer
      // that wastes an afternoon.
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status >= 300 && res.status < 400) {
      const to = res.headers.get('location') || '(unknown)';
      process.stderr.write(`  ⚠ ${apiUrl} redirects to ${to.split('/api/')[0]} — org settings skipped; point --api-url at the app host.\n`);
      return null;
    }
    if (!res.ok) return null;
    const j = await res.json().catch(() => null);
    if (!j) return null;
    return {
      secretAllowlist: Array.isArray(j.secretAllowlist) ? j.secretAllowlist : [],
      pathExclusions: Array.isArray(j.pathExclusions) ? j.pathExclusions : [],
      // Older platforms simply omit the field — an old server plus a new CLI
      // means no platform suppressions, never a crash.
      suppressionRules: Array.isArray(j.suppressionRules)
        ? j.suppressionRules.map(normalizeRule).filter(Boolean)
        : [],
    };
  } catch {
    return null;
  }
}
