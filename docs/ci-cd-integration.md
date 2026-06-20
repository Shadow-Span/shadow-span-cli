# CI/CD Integration

`shadow-span` runs the same engines locally that the Shadow Span platform runs —
**your source never leaves your runner**; only normalized finding metadata is sent
(and only when `--report` is set). The build gate is the CLI's **exit code**, so it
works in any CI today; native wrappers and PR/MR comments are layered on top.

| Surface | Status |
|---|---|
| Local CLI / any CI (exit-code gate) | ✅ available now |
| Pre-commit hook | ✅ available now |
| GitHub Actions (wrapper + PR comments + inline) | ✅ available now |
| GitLab CI (wrapper + MR comments + native reports) | 🛣️ roadmap — works today via the generic-CI recipe |
| Bitbucket Pipelines (Pipe + Code Insights) | 🛣️ roadmap — works today via the generic-CI recipe |

## Exit codes (the gate)

| Code | Meaning |
|---|---|
| `0` | clean, or gate passed, or `--mode alert` |
| `1` | findings at or above `--fail-on` (gate failed → build red) |
| `2` | scan or usage error |

`--fail-on none\|low\|medium\|high\|critical` (default `high`) · `--mode block` (default)
or `alert` (warn, exit 0) · `--soft-fail` (alias for alert).

## Authentication

- **Reporting to the platform** (`--report`): an API key with the `WRITE_APPSEC`
  scope, created in **Dashboard → Integrations → API Keys**. Store it as a CI secret
  named `SHADOWSPAN_API_KEY`. Identical across all CI systems.
- **PR/MR comments**: the CI platform's *own* token (never your Shadow Span key) —
  e.g. GitHub's `GITHUB_TOKEN`. Scoped to that repo only.

---

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]

permissions:
  contents: read
  pull-requests: write        # required for PR comments

jobs:
  appsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history — the secret scan walks all commits
      - uses: shadow-span/shadow-span-cli/actions/scan@v1
        with:
          api-key: ${{ secrets.SHADOWSPAN_API_KEY }}
          fail-on: high
          comment-on-pr: true
```

This posts an upsert-in-place **summary comment** plus **inline review comments** at
the exact file:line of each new finding, and fails the check when the gate trips.

## Pre-commit (local, blocks secrets before they're committed)

Uses the [pre-commit framework](https://pre-commit.com). The secret scan is
**local-only** — no network call, the secret value never leaves the machine.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/shadow-span/shadow-span-cli
    rev: v1.0.0
    hooks:
      - id: shadowspan-secrets          # blocks the commit on a secret
      # - id: shadowspan-secrets-alert  # non-blocking variant (warn only)
```

Bypass once: `SKIP=shadowspan-secrets git commit …`. No-framework alternative:
`shadow-span install-hook`.

---

## Generic CI (works on GitLab, Bitbucket, Jenkins, CircleCI… today)

Any CI can gate on the exit code right now. Run our Docker image (engines baked in)
or install the CLI, then call `shadow-span scan`.

### GitLab CI (available today via raw CLI; native MR comments on the roadmap)

```yaml
# .gitlab-ci.yml
appsec:
  image: ghcr.io/shadow-span/shadow-span-cli:1   # engines pre-installed
  variables:
    SHADOWSPAN_API_KEY: $SHADOWSPAN_API_KEY       # CI/CD variable (masked)
  script:
    - shadow-span scan --report --fail-on high --source cli
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

A failed gate fails the job → MR shows a failed pipeline. Native MR discussions +
inline comments and a `gl-sast-report.json` artifact (renders in the MR widget) are
on the roadmap — see the design note for the planned `--output gitlab` + reporter.

### Bitbucket Pipelines (available today via raw CLI; native Code Insights on the roadmap)

```yaml
# bitbucket-pipelines.yml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Shadow Span AppSec
          image: ghcr.io/shadow-span/shadow-span-cli:1
          script:
            - shadow-span scan --report --fail-on high --source cli
```

A failed gate fails the step → PR shows a failed build. Native Code Insights
annotations (in-diff file:line) are on the roadmap.

---

## Excluding paths — `.shadowspanignore`

Commit a `.shadowspanignore` at your repo root (gitignore-style globs) to drop
intentional fixtures, vendored code, or generated dirs from findings — *before* the
gate and *before* anything is reported:

```gitignore
**/__fixtures__/**
vendor/**
*.min.js
!important/keep-this.js   # negation re-includes
```

See [configuration.md](./configuration.md) for the full flag/env reference and
[security-and-data-handling.md](./security-and-data-handling.md) for exactly what is
(and isn't) transmitted.
