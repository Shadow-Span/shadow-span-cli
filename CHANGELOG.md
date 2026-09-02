# Changelog

All notable changes to `@shadow-span/cli`.

## 0.2.0 — 2026-09-02

The headline is a security review of the CLI and its engines, plus per-finding
suppression. **Read "Behaviour changes" before upgrading** — two of them can turn a
previously-green pipeline red, in both cases because it was green for the wrong
reason.

### Behaviour changes

- **A missing engine binary now fails the scan instead of passing it.** Every
  requested engine is checked before scanning; if one is unavailable the run exits
  `2` with the binary name and how to install it. Previously the failure was
  collected and the gate still passed, so a runner without `gitleaks` reported
  "no findings" on a repository containing live credentials. There is deliberately
  no flag to skip the check — to scan with fewer engines, ask for fewer with
  `--engines`.

- **An unrecognised `--fail-on` value is now rejected (exit `2`) instead of
  silently falling back to `high`.** With `unknown` added to the vocabulary (below),
  a typo could *loosen* the gate rather than tighten it: `--fail-on Unknown` passed
  a build that had open findings.

- **Fewer false positives.** SAST and IaC rule precision was corrected — most
  visibly the SQL-injection rule, which matched every backtick-quoted query rather
  than only interpolating ones. Expect a smaller, more accurate finding count.

### Added

- **`.shadowspan-suppressions.json`** — accept a single finding, with a mandatory
  reason and expiry:

  ```json
  {
    "suppressions": [
      { "matchType": "RULE_ID", "value": "CVE-2026-1234",
        "expiresAt": "2027-03-01",
        "reason": "No fixed version published; we never call the affected API.",
        "upstream": "https://github.com/advisories/…" }
    ]
  }
  ```

  Only `RULE_ID` and `PACKAGE` are accepted — each names one finding. Broad
  matchers (`PATH_GLOB`, `FINDING_TYPE`, `ECOSYSTEM`, `CWE`) are rejected, because
  one entry using them silences a whole class while reading like a narrow exception
  in a diff. Expiry is capped at 365 days and an expired entry simply stops
  suppressing, so an acceptance cannot become permanent by neglect. **Malware can
  never be suppressed.** Prefer this over a path exclude for an unfixable advisory —
  excluding the manifest also hides every future advisory in it.

- **Organization suppression rules are honoured.** A risk accepted in the Shadow
  Span dashboard now also stops blocking your pipeline, instead of the same finding
  being green in one place and red in the other. Requires a platform new enough to
  return them; older ones are handled gracefully.

- **`--fail-on unknown`** — a zero-tolerance bar that blocks every open finding,
  including unscored ones. The levels below it cannot express this: an
  UNKNOWN-severity finding outranks nothing, so it never blocked at any threshold —
  and most Go advisories carry no CVSS vector at all.

- **Suppressed findings are visible in machine-readable output.** SARIF results
  carry the native `suppressions[]` array with the justification, and
  `--output json` gains a `suppressed[]` block. Previously an accepted risk was
  indistinguishable from a finding that never existed.

- **PR-gate base inference on GitLab and Bitbucket**, not only GitHub. The same
  product gated on changed files under GitHub and on the entire tree elsewhere,
  which meant a permanently red pipeline on any repo with pre-existing findings.

### Security

Found in a pre-release review of the CLI and its engines. Each was reproduced
before and after the fix.

- **Argument injection hardening in the container engine.** Image names parsed out
  of a Dockerfile were passed to the scanner without terminating flag parsing, so a
  repository-controlled value could be read as an option rather than an image. Fixed
  at both the parser and the call site. Note this engine is **not reachable from the
  CLI** — it is not in `--engines` and nothing invokes it here; the code ships as part
  of the shared engine and the fix is included for completeness.

- **Private keys could be uploaded in code context.** Redaction ran per line, and
  the PEM pattern spans a whole key block, so only the `BEGIN` header was masked and
  the base64 body was sent with the finding. Files are now redacted whole, with line
  numbering preserved.

- **A crafted allowlist entry could disable secret scanning.** Values were embedded
  in the generated gitleaks TOML config guarded only against the quote delimiter; a
  newline allowed arbitrary config, including an allowlist that matched everything —
  while the scan still reported success.

- **Denial of service via glob matching.** Suppression and `.shadowspanignore`
  patterns compiled to backtracking regexes: a 43-character pattern took over two
  minutes. Matching is now linear.

- **Path exclusions bypassed the malware exemption.** `.shadowspanignore` and
  org path rules filtered on path alone, so a malicious package under an excluded
  directory was dropped — and malware lives in `node_modules`, which is excluded by
  default.

- **Log integrity.** Control characters in a suppression reason could overwrite the
  line recording that a finding had been suppressed.

- **Scanner subprocesses no longer inherit `SHADOWSPAN_API_KEY`**, and file reads
  during enrichment are bounded to the repository.

### Fixed

- The PR comment counted only the gated subset while listing every finding, so it
  could read "5 high" above a table of 24.
- Pointing `--api-url` at a host that redirects (a marketing domain in front of the
  app host) failed as `HTTP 405: unknown error`. The CLI no longer follows such a
  redirect and names the host to use — credentials do not survive a cross-origin hop.

## 0.1.1 — 2026-08-19

First public release.
