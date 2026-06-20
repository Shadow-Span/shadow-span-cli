# Security & Data Handling

This document states precisely what `shadow-span` executes, what data leaves your
infrastructure, and what never does. It is written for security review.

## TL;DR

- **Your source code never leaves your machine/runner.** The engines run locally.
- **Only normalized finding *metadata* is transmitted, and only when `--report` is
  set.** No file contents are uploaded as artifacts; only the small code clip around
  a finding (with secrets redacted) travels, as finding evidence.
- **Secret *values* are never transmitted or stored** — anywhere, by anyone (the
  rotation rule, below).
- The pre-commit secret scan is **fully local and offline** — zero network calls.

## What runs

`shadow-span` shells out to four open-source engine binaries (no network egress from
the engines themselves except the SCA engine's vulnerability-DB lookups):

| Engine | Tool | License | Talks to network? |
|---|---|---|---|
| Secrets | gitleaks | MIT | No |
| SAST | ast-grep + our rule packs | MIT | No |
| SCA (deps) | osv-scanner | Apache-2.0 | Yes — queries the public OSV.dev vuln database |
| IaC | Trivy (config) | Apache-2.0 | Yes — pulls Trivy's public misconfig policy DB |

Findings from every engine are converted into Shadow Span's own normalized format —
raw engine output is never surfaced.

## What is transmitted (only with `--report`)

When you pass `--report`, the CLI POSTs to `POST /api/v1/appsec/scans` over HTTPS,
authenticated by your `WRITE_APPSEC` API key. The body contains, per finding:

- rule id, rule name, type (SAST/SCA/SECRET/IAC), severity
- file path + line/column
- a stable one-way fingerprint (identity key)
- description + remediation text (authored by us, not your code)
- for SCA: package name / version / ecosystem / fixed version / CVE id
- `evidence`: a small **redacted** code-context window (±3 lines) for SAST/IaC, or
  redacted metadata (rule, commit, line, entropy) for secrets

It does **not** contain: whole files, your repository archive, environment variables,
or secret values.

Omit `--report` (or use `--no-report`) to run entirely locally — the gate still works.

## The rotation rule — secret values are never persisted

If a scanner ever stored a live secret, you'd have to rotate it just for having run
the tool. We don't:

1. **gitleaks runs with `--redact`** — secret values are masked in the engine's own
   output before we ever see them.
2. **The normalizer drops** the `Secret`/`Match` fields — a finding object never
   contains the value.
3. **Adjacent-line redaction** — a secret sitting *next to* a SAST/IaC finding (and
   thus inside that finding's code-context window) is redacted to `«REDACTED»` before
   the snippet becomes evidence. (We caught and closed this exact leak class in
   testing.)
4. **Server-side defense in depth** — the ingest API re-strips any secret-bearing
   key and re-redacts credential patterns from all evidence strings, even if a client
   sent them.

Net: a secret value never leaves your machine, and even if one somehow did, it is
never written to the platform database.

## Credentials

- **`WRITE_APPSEC` API key** — write-only; it can record findings for your
  organization and nothing else (no read of other data). Created and revocable in
  Dashboard → Integrations → API Keys; store it as a CI secret. Rotate at will.
- **The key is read from `--api-key`, the `SHADOWSPAN_API_KEY` env var, or
  `~/.config/shadowspan/config.json` (mode 600)** — in that order. Prefer the env var
  in CI so the key never appears in process arguments / logs.
- **PR/MR comments** use the CI platform's own token (e.g. GitHub `GITHUB_TOKEN`),
  never your Shadow Span key.

## Multi-tenancy / isolation

Findings are scoped to the organization that owns the API key — **server-side, from
the key**, never from anything in the request body. One org's key cannot write to
another org. The ingest endpoint is gated on the `AppSec` module entitlement, rate-
limited per key, and validates/sanitizes all input as hostile.

## Third-party licenses

All bundled engines are permissively licensed (MIT / Apache-2.0); full notices ship
in `THIRD_PARTY_NOTICES.md` inside the npm package and the Docker image.
