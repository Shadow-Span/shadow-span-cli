# Shadow Span IaC rule pack

Our own IaC misconfiguration checks, authored as **Trivy custom Rego checks**.
Trivy is the commodity engine (it parses HCL/CloudFormation/k8s/Dockerfile and
runs the OPA/Rego evaluator); the rules and remediation are ours — the same
"rent the engine, own the rules" model as the SAST pack (`engine/rules/sast/`).

## Layout

```
iac/
  mappings.json     # rule id → compliance controls (the core-pack table). SSOT.
  <provider>/*.rego # our checks (SS-* ids), one concern per file
  _fixtures/<rule>/{fail,pass}/  # self-contained tf that MUST / MUST NOT trip
```

## Running the pack

```sh
trivy config \
  --config-check engine/rules/iac \
  --check-namespaces user \
  --misconfig-scanners terraform \
  --format json <target>
```

Built-in Trivy checks still run alongside ours (augment, don't fork). Findings —
built-in and ours — are normalized in `engine/src/normalize.js`, which joins
`ruleId → mappings.json` to attach compliance frameworks to every finding.

## Authoring a rule — two gotchas that cost real debugging

1. **Selector `type` must match the schema.** A check that reads Trivy's
   cloud-adapted model (`input.aws.*`, `schemas: - input: schema["cloud"]`) MUST
   select `type: cloud`. `type: terraform` is only for checks that read raw HCL
   blocks (`schema["terraform"]`) — used with the cloud schema the check LOADS
   but SILENTLY NEVER EVALUATES (no error, no result).

2. **No `frameworks:` (or any nested map) in the `# METADATA` custom block.** A
   nested map under an unrecognized custom key silently breaks evaluation the
   same way. Compliance mappings therefore live in `mappings.json`, keyed by
   rule id — never in the Rego metadata.

Safe metadata keys (proven): `title`, `description`, `scope`, `schemas`,
`related_resources` (→ finding PrimaryURL), and under `custom`: `id`, `avd_id`,
`provider`, `service`, `severity`, `short_code`, `recommended_action`
(→ finding Resolution/remediation), `input.selector`.

## Rule checklist

- [ ] `id`/`avd_id` = `SS-<PROVIDER>-<SERVICE>-<NNN>`, package `user.<provider>.<name>`
- [ ] `recommended_action` written as an imperative fix (it becomes the remediation)
- [ ] `_fixtures/<rule>/fail/` trips it, `_fixtures/<rule>/pass/` does not
- [ ] entry in `mappings.json` with all five frameworks + `owned: true`
- [ ] covered by `src/__tests__/iac-rules.test.js`

Reference implementation: `aws/rds001_public_access.rego` (SS-AWS-RDS-001).
