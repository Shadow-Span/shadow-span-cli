// Fetch the org's AppSec scanner settings (secret allowlist + path exclusions)
// so they apply to local + CI runs. The SECRET ALLOWLIST especially must come
// from here — it's value-based and runs at gitleaks time on this machine, so it
// can't be enforced server-side at ingest (the matched value never leaves). Path
// exclusions are also returned (the server enforces those at ingest too; applying
// them here keeps the LOCAL gate result consistent). Best-effort: any failure
// returns null and the scan proceeds with no org settings — never blocks.

export async function fetchAppSecSettings({ apiUrl, apiKey, timeoutMs = 10000 }) {
  if (!apiUrl || !apiKey) return null;
  try {
    const res = await fetch(`${apiUrl}/api/v1/appsec/settings`, {
      headers: { Authorization: `Bearer ${apiKey}`, 'User-Agent': 'shadow-span-cli' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    const j = await res.json().catch(() => null);
    if (!j) return null;
    return {
      secretAllowlist: Array.isArray(j.secretAllowlist) ? j.secretAllowlist : [],
      pathExclusions: Array.isArray(j.pathExclusions) ? j.pathExclusions : [],
    };
  } catch {
    return null;
  }
}
