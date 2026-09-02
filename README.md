# shadow-span

Run Shadow Span's AppSec checks — **secrets, SCA, SAST, IaC** — in your own
developer workflow. The engines run **locally**; your source never leaves your
machine. Findings are normalized to Shadow Span's format, gate your commit/build
by severity, and can optionally be reported to the platform.

## Install

```sh
npm install -g @shadow-span/cli
# or run ad-hoc:  npx @shadow-span/cli scan
```

Requires the engine binaries on your `PATH`: `gitleaks`, `ast-grep`,
`osv-scanner`, `trivy`. (The GitHub Action ships them pre-installed.)

## Quick start

```sh
# Authenticate once (key needs the WRITE_APPSEC scope; stored 0600).
shadow-span auth --api-key ss_live_...

# Full scan of the current repo, fail the shell on HIGH+ findings.
shadow-span scan --fail-on high

# Scan + upload findings to the platform.
shadow-span scan --report

# Install a local-only secret pre-commit hook (no framework needed).
shadow-span install-hook
```

## Pre-commit (recommended: the pre-commit framework)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/shadow-span/shadow-span-cli
    rev: v0.1.0
    hooks:
      - id: shadowspan-secrets   # local-only; blocks commits that add secrets
```

The pre-commit secret scan is **local-only** — it makes no network call and the
secret value never leaves your machine. Bypass a single commit with
`SKIP=shadowspan-secrets git commit …` (framework) or `SKIP_SHADOWSPAN=1 git
commit …` (raw hook).

## Commands & flags

| | |
|---|---|
| `scan [path]` | run engines → render → exit per gate |
| `--engines` | `secret,sca,sast,iac` (default: all) |
| `--staged` | fast path: secrets + SAST (pre-commit) |
| `--diff` | mark partial (won't close prior findings) |
| `--fail-on` | `none\|low\|medium\|high\|critical\|unknown` (default `high`). `unknown` blocks every finding, including unscored ones. |
| `--soft-fail` | never exit non-zero on findings |
| `--report` / `--no-report` | upload findings (opt-in; off by default for `--staged`) |
| `--output` | `rich` (default) or `json` |
| `--comment-pr` | (GitHub Action) PR summary + inline comments |
| `auth --api-key` | store credentials (`~/.config/shadowspan/`, 0600) |
| `install-hook [--force]` | write a local git pre-commit hook |

Exit codes: `0` clean / gate passed · `1` findings at or above `--fail-on` · `2`
scan or usage error.

## Gating a pull request

Scanning a whole repo and failing on everything found means a repo with any existing
findings has a permanently red gate — and a gate that is always red is one people
learn to ignore. Point `--diff-base` at the branch you are merging into and only
findings in files **this branch changed** can fail the build:

```sh
shadow-span scan --fail-on high --diff-base origin/main
```

Everything is still scanned and still reported; the narrowing applies solely to what
blocks. Needs full history (`fetch-depth: 0` in GitHub Actions) — if the base cannot
be resolved the CLI says so and gates on *everything*, rather than silently passing.

The GitHub Action does this by default.

## Excluding paths

Commit a `.shadowspanignore` at the repo root — gitignore syntax, including `!`
negation:

```
**/__fixtures__/**
vendor/**
!vendor/keep-scanning-me/**
```

Suppressed findings are counted and reported (with the rule that matched) when
`--report` is on, so an exclusion is visible in the platform rather than silent.
Organization-wide exclusions are configured in Shadow Span and apply on top.

## Accepting a single finding

Use a path exclude to skip code you never want scanned. Use a **suppression** to
accept one specific finding you have looked at and decided not to act on — a
vulnerability with no fix published, or one you have established you don't reach.

Commit a `.shadowspan-suppressions.json` at the repo root:

```json
{
  "suppressions": [
    {
      "matchType": "RULE_ID",
      "value": "CVE-2026-1234",
      "expiresAt": "2027-03-01",
      "reason": "No fixed version published. We never call the affected API — verified with `go list -deps`.",
      "upstream": "https://github.com/org/repo/issues/1"
    }
  ]
}
```

| Field | | |
|---|---|---|
| `matchType` | required | `RULE_ID` (an advisory: `CVE-…`, `GHSA-…`, `GO-…`), `PACKAGE` (a dependency name), or `CWE` |
| `value` | required | what to match |
| `expiresAt` | required | `YYYY-MM-DD`, at most 365 days out |
| `reason` | required | why this is acceptable — the next person to read it is the one deciding whether to renew |
| `upstream` | optional | link to the advisory or upstream issue |

Rules of the format, and why:

- **Expiry is mandatory and capped at a year.** An expired entry simply stops
  suppressing, so the finding starts blocking again on its own. A suppression
  cannot become permanent by neglect.
- **Only precise match types.** `PATH_GLOB`, `FINDING_TYPE` and `ECOSYSTEM` are
  rejected here on purpose — a single entry using one of them could silence a
  whole class of findings, and it would look like ordinary config in a diff. Use
  `.shadowspanignore` for paths, or an org rule in the platform, where the
  decision is attributable and audited.
- **Malware can never be suppressed.** A package flagged as malicious is an
  incident, not a finding to accept, whatever a rule claims to match.
- **Prefer a suppression over a path exclude for an unfixable advisory.**
  Excluding the manifest hides every *future* advisory in it too.

Org-wide suppression rules created in Shadow Span are fetched and applied as
well, so a risk accepted in the dashboard also stops blocking your pipeline.

## Connecting to the platform

`--report` needs two things: a key with the **WRITE_APPSEC** scope, and the
**app** host.

```bash
export SHADOWSPAN_API_KEY=ss_live_...
shadow-span scan --report --api-url https://app.shadowspan.com
```

**Point `--api-url` at the app host, not your marketing domain.** If the two are
different hostnames and the marketing one redirects to the app one, the request
does not survive the hop: browsers and Node both strip the `Authorization` header
across a cross-origin redirect, and a 301 turns a POST into a GET. The result is
an authentication failure that has nothing to do with your key.

The CLI refuses to follow such a redirect and tells you the host to use instead:

```
✗ Report failed (HTTP 301): https://shadowspan.com redirects to
  https://app.shadowspan.com. Point --api-url (or SHADOWSPAN_API_URL) at
  https://app.shadowspan.com — credentials are not carried across a redirect,
  so the scan would be rejected.
```

Use an **organization** key rather than a personal one for CI. A personal key's
scopes are intersected with its owner's current access on every request, so it
narrows the moment that person changes role or leaves — which is correct for a
human, and an outage for a pipeline.

## What is sent to the platform

**Nothing, unless you pass `--report`.** Without it the CLI is entirely local: it
runs the engines, prints results, and sets an exit code.

With `--report`, what leaves your machine is normalized finding **metadata** against
an explicit allowlist — rule id, severity, file path, line, package/CVE identifiers,
and a one-way fingerprint used to de-duplicate across scans. Plus the repository
identity (provider/owner/name), the commit sha and branch, and a count of what your
`.shadowspanignore` suppressed.

**Your source code is never transmitted.** No file contents, no diffs, no snippets.

**Secret values are never transmitted.** Two independent layers, either of which
would be sufficient: gitleaks runs with `--redact`, and the normalizer drops the
`Secret`, `Match`, `Author` and `Email` fields before a finding object is even
constructed. A finding tells the platform *that* a credential was found at
`path:line` and which rule matched — never the credential.

## Security

**Your API key.** Stored at `~/.config/shadowspan/config.json` with mode `0600`,
never written to logs and never passed on the command line to a subprocess (so it
cannot appear in CI output or a process list). It is a write-scoped `WRITE_APPSEC`
token: it can submit findings, it cannot read your data.

**`--api-url` is refused over plaintext.** The key is a bearer credential, so the CLI
will not send it over `http://` to anything but loopback — a mistyped or tampered
value cannot exfiltrate it in the clear.

**No runtime dependencies.** `npm ls` on this package is empty by design: the scanning
kernel is vendored, so installing it does not pull a transitive tree you then have to
trust. The engines are separate pinned binaries you install yourself.

**Engines are invoked without a shell.** Arguments are passed as an array, so a file
or branch name containing shell metacharacters cannot inject a command.

Found a security issue? Email **security@shadowspan.com**.

## Licensing

This CLI is Apache-2.0. The engines it drives are separate, permissively licensed
programs invoked as subprocesses — gitleaks (MIT), ast-grep (MIT), osv-scanner
(Apache-2.0), Trivy (Apache-2.0). Attribution is in `THIRD_PARTY_NOTICES.md`, which
ships with the package; please keep it intact.
