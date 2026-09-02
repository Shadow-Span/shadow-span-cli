// Environment handed to scanner subprocesses.
//
// The engines shell out to trivy / gitleaks / ast-grep / osv-scanner / bicep
// while scanning a repository we do not trust, and by default a child inherits
// the whole environment — including SHADOWSPAN_API_KEY, the WRITE_APPSEC token
// the CLI reports with. There is no proven exfiltration path today (none of
// these tools forward their environment to a remote), but "the scanner has no
// reason to hold our token" is a cheaper invariant to keep than to re-audit
// every time one of them gains a feature. Flagged in a pre-release security
// review, 2026-09-02, alongside the trivy argument-injection finding — which is
// exactly the scenario where an attacker-configured tool runs in this process.
//
// DENY-LIST, not an allow-list, on purpose: the tools legitimately need PATH,
// HOME, XDG_*, proxy settings, registry credentials and a long tail of platform
// variables. Removing the few we know are ours cannot break a scan; whitelisting
// would, on somebody's runner, in a way we would not see until it did.

const STRIPPED = ['SHADOWSPAN_API_KEY'];

/**
 * @param {NodeJS.ProcessEnv} [base]  defaults to process.env
 * @param {object} [extra]            variables to add (e.g. XDG_CACHE_HOME)
 */
export function scannerEnv(base = process.env, extra = {}) {
  const out = { ...base, ...extra };
  for (const k of STRIPPED) delete out[k];
  return out;
}

export const _STRIPPED = STRIPPED;
