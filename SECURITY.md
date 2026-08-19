# Security Policy

## Reporting a vulnerability

Email **security@shadowspan.com**. Please do not open a public issue for a security report.

Include what you need to make it reproducible — the command, the version (`shadow-span version`),
and what you observed versus expected. If you have a proof of concept, attach it; if it involves a
credential of yours, redact it.

We aim to acknowledge within **2 business days** and to keep you updated as we work. If you would
like credit in the release notes, say so and tell us how you would like to be named.

## Supported versions

The latest published minor is supported. This project is pre-1.0, so fixes land on the newest
version rather than being backported.

## Scope

This CLI runs security engines against **your** code, on **your** machine. The parts most worth
your attention:

- **Your API key.** Stored at `~/.config/shadowspan/config.json` with mode `0600`, never logged,
  and passed to subprocesses via the environment rather than argv so it cannot appear in CI output
  or a process list. It is a write-scoped `WRITE_APPSEC` token: it can submit findings, it cannot
  read your data.
- **Where that key is sent.** `--api-url` is refused over plaintext to anything but loopback, so a
  mistyped or tampered value cannot exfiltrate it in the clear.
- **What leaves your machine.** Nothing unless you pass `--report`. With it, normalized finding
  metadata against an explicit allowlist — never file contents, and never secret values (gitleaks
  runs with `--redact` and the normalizer drops the value before a finding object exists).
- **Engine invocation.** Engines are executed with `execFile` and array arguments, never through a
  shell, so a file or branch name containing shell metacharacters is inert.

Findings produced *about your code* are not vulnerabilities in this tool. A false positive is a
bug — please report it as a normal issue.

## Out of scope

- The engine binaries themselves (gitleaks, ast-grep, osv-scanner, Trivy). Report those upstream;
  we will happily help you route it.
- The Shadow Span platform API. Same address, but say so in the subject.
