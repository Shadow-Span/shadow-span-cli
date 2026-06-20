# shadow-span

Run Shadow Span's AppSec checks — **secrets, SCA, SAST, IaC** — in your own
developer workflow. The engines run **locally**; your source never leaves your
machine. Findings are normalized to Shadow Span's format, gate your commit/build
by severity, and can optionally be reported to the platform.

## Install

```sh
npm install -g shadow-span-cli
# or run ad-hoc:  npx shadow-span-cli scan
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
| `--fail-on` | `none\|low\|medium\|high\|critical` (default `high`) |
| `--soft-fail` | never exit non-zero on findings |
| `--report` / `--no-report` | upload findings (opt-in; off by default for `--staged`) |
| `--output` | `rich` (default) or `json` |
| `--comment-pr` | (GitHub Action) PR summary + inline comments |
| `auth --api-key` | store credentials (`~/.config/shadowspan/`, 0600) |
| `install-hook [--force]` | write a local git pre-commit hook |

Exit codes: `0` clean / gate passed · `1` findings at or above `--fail-on` · `2`
scan or usage error.

## What is sent to the platform

Only when `--report` is set: normalized finding **metadata** (rule, file, line,
severity, a one-way fingerprint). **Secret values are never transmitted** —
gitleaks runs with `--redact` and the normalizer drops the value before a finding
is ever created.

## Licensing

Engines are permissive-licensed (gitleaks MIT, ast-grep MIT, osv-scanner
Apache-2.0, Trivy Apache-2.0); see `THIRD_PARTY_NOTICES.md`.
