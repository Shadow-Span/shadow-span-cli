// shadow-span — entry dispatch. `run(argv)` returns a process exit code
// (testable; the bin wrapper calls process.exit with it).
//
// Exit codes (Aikido/Cycode convention):
//   0  clean / gate passed
//   1  findings at or above --fail-on (gate blocked)
//   2  scan error — usage error, a missing engine binary (preflight), or ANY engine failing
//      mid-scan. Not "all engines failed": one dead engine means the scan is incomplete, and a
//      passing gate on an incomplete scan is a false statement.

import { parseArgs } from 'node:util';
import path from 'node:path';
import { access, writeFile, chmod } from 'node:fs/promises';
import { evaluateGate, FAIL_ON_LEVELS, scanDast, scanZap, preflight, formatPreflightFailure } from '../engine/src/index.js';
import { applyPathExclusions } from '../engine/src/lib/path-exclude.js';
import { loadSuppressionFile, applySuppressions, SUPPRESSION_FILENAME } from '../engine/src/suppression-file.js';
import { sanitizeForLog } from '../engine/src/redact.js';
import { runEngines, ALL_ENGINES, FAST_ENGINES } from './scan.js';
import { fetchAppSecSettings } from './settings.js';
import { renderResults } from './render.js';
import { buildPayload, reportScan, buildDastPayload, reportDastScan } from './report.js';
import { postPrFeedback, detectProvider } from './reporters/index.js';
import { toSarif } from './formats/sarif.js';
import { toCodeQuality } from './formats/gitlab-codequality.js';
import { collectGitInfo, changedFiles, inferDiffBase } from './git-info.js';
import { resolveConfig, saveAuth, DEFAULT_API_URL } from './config.js';
import { loadIgnore, applyIgnore, IGNORE_FILENAME } from './ignore.js';

const VERSION = '0.1.0';

const HELP = `shadow-span v${VERSION} — run Shadow Span AppSec checks in your pipeline

USAGE
  shadow-span scan [path] [options]
  shadow-span dast --url <target> [options]   # active web scan (Nuclei)
  shadow-span auth --api-key <key> [--api-url <url>]
  shadow-span install-hook [--force]   # local-only secret pre-commit hook
  shadow-span version | help

SCAN OPTIONS
  --engines <list>   comma list of: secret,sca,sast,iac  (default: all)
  --staged           pre-commit fast path: secrets + SAST only, local-only by default
  --diff             mark this a partial scan (does not close prior findings)
  --fail-on <level>  none|low|medium|high|critical|unknown (default: high)
                     'unknown' blocks EVERY finding, including unscored ones
  --mode <m>         block (default: exit 1 on findings≥fail-on) | alert (warn, exit 0)
  --soft-fail        alias for --mode alert (never exit non-zero on findings)
  --report           POST findings to the Shadow Span platform (needs an API key)
  --no-report        force local-only (default for --staged)
  --scan-dependencies  also scan node_modules / venv / Pods (excluded by default —
                     use when hunting a supply-chain implant; expect volume)
  --api-key <key>    WRITE_APPSEC key (or env SHADOWSPAN_API_KEY)
  --api-url <url>    platform base URL (default: ${DEFAULT_API_URL})
  --source <s>       cli | github-action | pre-commit     (default: cli)
  --output <fmt>     rich | json                          (default: rich)
  --sarif <path>     write a SARIF 2.1.0 report (GitHub code-scanning, etc.)
  --gitlab-report <path>  write a GitLab Code Quality report (MR widget, token-free)
  --comment-pr       post PR/MR summary + inline file:line comments — auto-detects
                     GitHub / GitLab / Bitbucket from the CI environment

DAST OPTIONS (shadow-span dast)
  --url <target>     URL to actively scan (required; http/https)
  --tier <t>         deep (default — DAST, active app-vuln scan) | lite (DAST Lite,
                     fast exposure check)
  --browser          [deep] use the AJAX spider (Chrome) — for SPAs (the browser
                     image enables this automatically)
  --passive          [deep] passive baseline only (no active injection)
  --severity <list>  [lite] severities: critical,high,medium,low,info
  --templates <list> [lite] comma list of template dirs/files
  --engine <e>       advanced/back-compat alias for --tier: zap (=deep) | nuclei (=lite)
  --fail-on <level>  none|low|medium|high|critical|unknown (default: high)
                     'unknown' blocks EVERY finding, including unscored ones
  --mode <m>         block (default) | alert (warn, exit 0)
  --report           POST findings to Shadow Span (needs an API key + a
                     domain-verified, ACTIVE DAST target for --url)
  --output <fmt>     rich | json
  --sarif <path>     write a SARIF 2.1.0 report

  Engines: nuclei runs anywhere (binary baked into the DAST image). zap
  requires the ZAP image (shadow-span/appsec-zap-scan) — it returns nothing if
  the ZAP install isn't present.

DAST runs an ACTIVE scan — only point it at systems you are authorized to test
(your own pre-prod/staging). The platform additionally refuses --report unless
--url maps to a domain-verified, authorized target you registered.

REPO FILES (optional, committed alongside your code)
  .shadowspanignore              path excludes, gitignore-style globs
  .shadowspan-suppressions.json  accept ONE finding, with a reason + expiry:
    { "suppressions": [ { "matchType": "RULE_ID", "value": "CVE-2026-1234",
        "expiresAt": "2027-03-01", "reason": "not reachable — we never call it",
        "upstream": "https://github.com/org/repo/issues/1" } ] }
  Prefer a suppression over a path exclude for an unfixable advisory: excluding
  the manifest also hides every FUTURE advisory in it. Expiry is mandatory, an
  expired entry stops suppressing, and MALWARE can never be suppressed.

The engine binaries (gitleaks, ast-grep, osv-scanner, trivy, nuclei) run locally;
your source never leaves your machine. Only normalized finding metadata is sent,
and only when --report is set. Secret VALUES are never transmitted.`;

const OPTIONS = {
  'api-key': { type: 'string' },
  'api-url': { type: 'string' },
  engines: { type: 'string' },
  url: { type: 'string' },
  severity: { type: 'string' },
  templates: { type: 'string' },
  tier: { type: 'string' },
  engine: { type: 'string' },
  browser: { type: 'boolean' },
  passive: { type: 'boolean' },
  'fail-on': { type: 'string' },
  mode: { type: 'string' },
  source: { type: 'string' },
  output: { type: 'string' },
  sarif: { type: 'string' },
  'gitlab-report': { type: 'string' },
  staged: { type: 'boolean' },
  diff: { type: 'boolean' },
  'diff-base': { type: 'string' },
  // Opt OUT of automatic PR-gate inference and judge every finding (see the gating block below).
  'no-pr-gate': { type: 'boolean' },
  report: { type: 'boolean' },
  'no-report': { type: 'boolean' },
  // Opt OUT of DEFAULT_EXCLUSIONS. Hunting a supply-chain implant inside node_modules is a real
  // task, and the noise filter must not be the thing that prevents it.
  'scan-dependencies': { type: 'boolean' },
  'comment-pr': { type: 'boolean' },
  'soft-fail': { type: 'boolean' },
  force: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
};

export async function run(argv, io = console) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    io.error(`Error: ${err.message}\n`);
    io.error(HELP);
    return 2;
  }
  const { values: flags, positionals } = parsed;
  const cmd = positionals[0] || (flags.version ? 'version' : flags.help ? 'help' : 'help');

  if (cmd === 'version') { io.log(VERSION); return 0; }
  if (cmd === 'help' || flags.help) { io.log(HELP); return 0; }
  if (cmd === 'auth') return cmdAuth(flags, io);
  if (cmd === 'scan') return cmdScan(flags, positionals.slice(1), io);
  if (cmd === 'dast') return cmdDast(flags, positionals.slice(1), io);
  if (cmd === 'install-hook') return cmdInstallHook(flags, io);

  io.error(`Unknown command: ${cmd}\n`);
  io.error(HELP);
  return 2;
}

async function cmdAuth(flags, io) {
  const apiKey = flags['api-key'] || process.env.SHADOWSPAN_API_KEY;
  if (!apiKey) {
    io.error('auth: provide --api-key <key> (or set SHADOWSPAN_API_KEY).');
    return 2;
  }
  const file = await saveAuth({ apiKey, apiUrl: flags['api-url'] });
  io.log(`Saved credentials to ${file} (mode 600).`);
  return 0;
}

async function cmdInstallHook(flags, io) {
  // Convenience for teams NOT using the pre-commit framework (the recommended
  // path is .pre-commit-config.yaml). Writes a raw git pre-commit hook that runs
  // a LOCAL-ONLY secret scan — no network, blocks the commit on a secret.
  const gitDir = path.resolve('.git');
  try { await access(gitDir); } catch {
    io.error('install-hook: no .git directory here — run inside a git repo.');
    return 2;
  }
  const hookPath = path.join(gitDir, 'hooks', 'pre-commit');
  let exists = false;
  try { await access(hookPath); exists = true; } catch { /* none */ }
  if (exists && !flags.force) {
    io.error(`install-hook: ${hookPath} already exists. Re-run with --force to overwrite, or use the pre-commit framework instead.`);
    return 2;
  }
  const script = `#!/bin/sh
# Shadow Span AppSec — local-only secret scan. Blocks the commit on a secret.
# The secret value never leaves this machine. Bypass once: SKIP_SHADOWSPAN=1 git commit
[ -n "$SKIP_SHADOWSPAN" ] && exit 0
exec shadow-span scan --staged --engines secret --no-report --fail-on critical
`;
  await writeFile(hookPath, script, { mode: 0o755 });
  await chmod(hookPath, 0o755).catch(() => {});
  io.log(`Installed local secret-scan pre-commit hook at ${hookPath}.`);
  return 0;
}

async function cmdScan(flags, restPositionals, io) {
  const repoPath = path.resolve(restPositionals[0] || flags._path || '.');

  // Engine selection.
  let engines = ALL_ENGINES;
  if (flags.engines) {
    engines = flags.engines.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  } else if (flags.staged) {
    engines = FAST_ENGINES;
  }
  const bad = engines.filter((e) => !ALL_ENGINES.includes(e));
  if (bad.length) { io.error(`Unknown engine(s): ${bad.join(', ')}. Valid: ${ALL_ENGINES.join(', ')}`); return 2; }

  // Normalize case, and REJECT an unrecognized level instead of falling back.
  // A silent fallback to 'high' used to be harmless because 'high' was stricter
  // than most typos; with 'unknown' in the vocabulary it became a way to LOOSEN
  // the gate by mistyping — `--fail-on Unknown` passed a build with open
  // findings. A security gate must never quietly grade itself easier.
  const failOnRaw = flags['fail-on'];
  const failOn = failOnRaw === undefined ? 'high' : String(failOnRaw).toLowerCase();
  if (!FAIL_ON_LEVELS.includes(failOn)) {
    io.error(`Invalid --fail-on '${failOnRaw}'. Use one of: ${FAIL_ON_LEVELS.join(' | ')}`);
    return 2;
  }
  const scanType = (flags.staged || flags.diff) ? 'diff' : 'full';
  const source = flags.source || (flags.staged ? 'pre-commit' : 'cli');
  const output = flags.output === 'json' ? 'json' : 'rich';

  // --mode block (default) blocks the commit/build (exit 1) on findings at or
  // above --fail-on. --mode alert surfaces findings but never blocks (exit 0) —
  // for teams rolling out the hook gradually. --soft-fail is the legacy alias.
  if (flags.mode && !['block', 'alert'].includes(flags.mode)) {
    io.error(`Invalid --mode '${flags.mode}'. Use: block | alert`); return 2;
  }
  const alertOnly = flags.mode === 'alert' || Boolean(flags['soft-fail']);

  // Load + validate .shadowspan-suppressions.json BEFORE scanning, so a typo in
  // the file is reported in a second rather than after a full scan. A config we
  // cannot parse must never be treated as "no suppressions configured" — a
  // malformed rule someone believes is protecting them would pass in silence.
  // (It is APPLIED after the engines run; see the suppression block below.)
  const suppression = await loadSuppressionFile(repoPath);
  if (suppression.errors.length) {
    for (const e of suppression.errors) io.error(`✖ ${e}`);
    return 2;
  }
  for (const w of suppression.warnings) io.error(`  ⚠ ${w}`);

  // --staged defaults to local-only (the rotation rule): the pre-commit hook
  // must not require network. --report opts back in; --no-report forces off.
  const wantReport = flags['no-report'] ? false : (flags.report ?? false);

  // Fetch org scanner settings so the SECRET ALLOWLIST (value-based → must run at
  // gitleaks time on THIS machine) applies to local + CI runs, and org path
  // exclusions are honored locally too. Networked only — the pre-commit path
  // (--staged) stays local-only unless --report. Best-effort; never blocks.
  let engineOpts = {};
  let orgPathExclusions = [];
  let orgSuppressions = [];
  if (wantReport || !flags.staged) {
    const cfg = await resolveConfig(flags);
    if (cfg.apiKey) {
      // Repo identity so the server can resolve scope=REPO suppression rules —
      // it is keyed by SourceRepository.id, which only the server knows.
      const { repo } = await collectGitInfo(repoPath).catch(() => ({ repo: null }));
      const s = await fetchAppSecSettings({ apiUrl: cfg.apiUrl, apiKey: cfg.apiKey, repo });
      if (s) {
        if (s.secretAllowlist?.length) engineOpts.allowlistRegexes = s.secretAllowlist;
        orgPathExclusions = s.pathExclusions || [];
        orgSuppressions = s.suppressionRules || [];
        if (output !== 'json' && (s.secretAllowlist?.length || orgPathExclusions.length || orgSuppressions.length)) {
          io.error(`  org settings: ${s.secretAllowlist?.length || 0} secret-allowlist, `
            + `${orgPathExclusions.length} path-exclusion, ${orgSuppressions.length} suppression rule(s)`);
        }
      }
    }
  }

  if (output !== 'json') io.error(`Scanning ${repoPath} [${engines.join(', ')}]…`);
  // PREFLIGHT. Prove every requested engine can run before scanning, so "no findings" cannot mean
  // "the scanner was not installed". A missing binary used to yield a green gate: runEngines
  // collected the failure into `errors`, and the exit check below only fired when EVERY engine
  // failed. Verified against the real image — with gitleaks moved aside, a repo containing a live
  // GitHub token reported "No findings / Gate passed" and exited 0.
  //
  // There is deliberately no --skip-preflight. The engine list IS the contract: to scan with fewer
  // engines, ask for fewer. A flag to proceed anyway would reopen exactly this hole.
  const pre = await preflight(engines);
  if (!pre.ok) {
    io.error(formatPreflightFailure(pre));
    return 2;
  }

  const { findings: rawFindings, errors } = await runEngines({
    repoPath,
    engines,
    engineOpts,
    onProgress: (m) => { if (output !== 'json') io.error(`  ${m}`); },
  });

  // Apply .shadowspanignore (repo-relative path excludes) + org path exclusions
  // BEFORE gate + report, so ignored paths neither block the build nor reach the
  // platform. (The server ALSO enforces org path exclusions at ingest.)
  const matcher = await loadIgnore(repoPath);
  let { kept: findings, ignored, byRule: suppressedRules } = applyIgnore(rawFindings, matcher);
  if (ignored > 0 && output !== 'json') {
    io.error(`  ${ignored} finding(s) excluded by ${IGNORE_FILENAME} (${matcher.count} rule(s))`);
  }
  // ALWAYS run this, not only when the org configured rules: DEFAULT_EXCLUSIONS (node_modules
  // and friends) live inside it. Gating the whole call on orgPathExclusions.length was why
  // 0.1.0 reported findings against `node_modules/@shadow-span/cli/...` on a local scan — the
  // engines only skip node_modules when the target is a git repo, and this filter, the one
  // layer that does not care about git, never ran.
  {
    const r = applyPathExclusions(findings, orgPathExclusions, {
      includeDefaults: !flags['scan-dependencies'],
    });
    if (r.dropped > 0 && output !== 'json') io.error(`  ${r.dropped} finding(s) excluded by path rules`);
    findings = r.findings;
  }

  // Apply .shadowspan-suppressions.json — per-FINDING suppression with a
  // mandatory reason + expiry. Distinct from .shadowspanignore on purpose:
  // silencing one unfixable advisory by excluding its manifest path would also
  // hide every future advisory in that manifest.
  //
  // Suppressed findings are dropped from BOTH the gate and the report, matching
  // how .shadowspanignore behaves — uploading them would show them as OPEN in the
  // dashboard (the server does not know about this file) while CI went green, and
  // a finding that is red in one place and green in the other teaches people to
  // trust neither. Carrying the acceptance + expiry through to the platform as
  // evidence is worth doing, but it needs the ingest payload to model it.
  let suppressedFindings = [];
  {
    // Repo file + platform rules are UNIONED. Both are deliberate acceptances by
    // someone with authority to make them, so either one suppressing is the
    // answer; requiring both would mean a dashboard acceptance still blocks CI,
    // which is the split this is here to close.
    const allRules = [...suppression.rules, ...orgSuppressions];
    if (allRules.length) {
      const r = applySuppressions(findings, allRules);
      findings = r.kept;
      suppressedFindings = r.suppressed;
      if (output !== 'json') {
        if (r.suppressed.length) {
          io.error(`  ${r.suppressed.length} finding(s) suppressed:`);
          for (const { finding: f, rule } of r.suppressed) {
            const where = rule.origin === 'platform'
              ? `platform (${rule.originScope}-scoped)`
              : SUPPRESSION_FILENAME;
            const until = rule.expiresOn
              ?? (rule.expiresAt ? new Date(rule.expiresAt).toISOString().slice(0, 10) : 'no expiry');
            // reason/value are attacker-controlled (a repo file, or a platform
            // rule stored with only trim+slice). Printed raw, a trailing CR plus
            // padding overwrites this very line, erasing the only record that a
            // finding was suppressed from the CI log.
            io.error(`    ${sanitizeForLog(f.ruleId, 100)} — ${where} — until ${until} — ${sanitizeForLog(rule.reason)}`);
          }
        }
        // Only nag about the repo file. A platform rule that matches nothing here
        // is normal — it may exist for a different repo, or for findings this
        // engine selection did not produce.
        for (const rule of r.unusedRules.filter((x) => x.origin !== 'platform')) {
          io.error(`  ⚠ suppression ${rule.matchType}=${sanitizeForLog(rule.value, 100)} matches nothing — remove it from ${SUPPRESSION_FILENAME}`);
        }
      }
    }
  }

  // ── PR gating ───────────────────────────────────────────────────────────────────────────────
  // With --diff-base, the GATE judges only findings in files this branch changed, while the report
  // still carries EVERYTHING. That split is the point: a repo with pre-existing findings otherwise
  // gets a permanently red gate, and a gate that is always red is one people learn to ignore. What
  // a PR is accountable for is what it changed.
  //
  // Scanning is unchanged — still whole-repo. Scoping the SCAN would be wrong: SCA needs the whole
  // lockfile and IaC needs surrounding context, so a file-limited scan reports different findings,
  // not fewer.
  //
  // The base is INFERRED from CI when not given explicitly. It used to be supplied only by the
  // GitHub Action's entrypoint, so the identical product gated on changed files under GitHub and on
  // the entire tree under GitLab and Bitbucket — a permanently red pipeline there for any repo with
  // standing findings. Inference makes the three behave the same. `--no-pr-gate` restores
  // judging everything, and the chosen base is always printed, so this is never silent.
  let gateFindings = findings;
  let diffBase = flags['diff-base'];
  if (!diffBase && !flags['no-pr-gate']) {
    const inferred = inferDiffBase();
    if (inferred) {
      diffBase = inferred.base;
      if (output !== 'json') io.error(`  PR gate: base inferred from ${inferred.from} → ${diffBase}`);
    }
  }
  if (diffBase) {
    const changed = await changedFiles(repoPath, diffBase);
    if (changed === null) {
      // Unknown, not empty. A shallow clone or unresolvable base must NOT silently pass the gate,
      // so fall back to judging everything and say so.
      if (output !== 'json') {
        io.error(`  diff-base '${diffBase}' could not be resolved — gating on ALL findings`);
        io.error('  (in CI this usually means a shallow checkout; use fetch-depth: 0)');
      }
    } else {
      gateFindings = findings.filter((f) => f.file && changed.has(f.file));
      if (output !== 'json') {
        io.error(`  gate scoped to ${changed.size} changed file(s): ${gateFindings.length} of ${findings.length} finding(s) in scope`);
      }
    }
  }

  const gate = evaluateGate(gateFindings, { failOn, softFail: alertOnly });

  // The gate judges a SUBSET (this PR's changed files) while every renderer lists ALL findings.
  // Counting the two populations with one number is how the PR comment came to read "5 high" above
  // a table of 24 HIGH rows. `scope` carries both so nothing has to guess which it was handed;
  // totals go through evaluateGate too, so there is exactly one counting implementation.
  const scope = gateFindings === findings ? null : {
    diffBase,
    gatedCount: gateFindings.length,
    totalCount: findings.length,
    totalBySeverity: evaluateGate(findings, { failOn: 'none' }).bySeverity,
  };

  io.log(renderResults({ findings, gate, scope, errors, suppressed: suppressedFindings, output }));

  // Native report artifacts (token-free; rendered by the SCM's own widgets).
  if (flags.sarif) {
    await writeFile(flags.sarif, JSON.stringify(toSarif(findings, { version: VERSION, suppressed: suppressedFindings }), null, 2));
    if (output !== 'json') io.error(`  wrote SARIF → ${flags.sarif}`);
  }
  if (flags['gitlab-report']) {
    await writeFile(flags['gitlab-report'], JSON.stringify(toCodeQuality(findings), null, 2));
    if (output !== 'json') io.error(`  wrote GitLab Code Quality report → ${flags['gitlab-report']}`);
  }

  // Report (opt-in). Failure to report never changes the gate result.
  if (wantReport) {
    const { apiKey, apiUrl } = await resolveConfig(flags);
    if (!apiKey) {
      io.error('⚠ --report set but no API key found (set SHADOWSPAN_API_KEY or run `shadow-span auth`). Skipping upload.');
    } else {
      const { repo, commit } = await collectGitInfo(repoPath);
      // Coordinate PR feedback: --comment-pr → the CLI posts from the runner
      // ('client'); otherwise, when running in a CI provider, ask the platform to
      // decorate via the connected App ('platform'); else 'none'. Prevents double-posting.
      const prComment = flags['comment-pr'] ? 'client' : (detectProvider() ? 'platform' : 'none');
      // Report what was SUPPRESSED alongside what was found. Without this the repo-local ignore
      // file is a silent channel: a rule of `**` turns the pipeline green and the platform sees a
      // clean scan with no sign anything was dropped. The org exclusion list is NOT included here —
      // the server applies that itself and already knows it; this is specifically the extra
      // filtering the RUNNER did on top.
      //
      // ACCEPTED-RISK SUPPRESSIONS ARE REPORTED, NOT WITHHELD. They gate locally
      // but they stay in the payload, for one blunt reason: on a FULL scan the
      // server closes every finding missing from the payload as REMEDIATED with a
      // fixedAt (appsec-engine findings.js). Dropping them here would make one
      // committed suppression file rewrite the customer's history to say a
      // vulnerability was FIXED when it was only accepted — silent data
      // corruption of a security record, from a security vendor.
      //
      // So the split is deliberate: the repo file is a decision about THIS
      // PIPELINE's gate, and the platform's own suppression rules are the
      // platform's decision about its dashboard. An org that wants a finding gone
      // from both creates a platform rule — which now flows back to the CLI and
      // gates too, so the two compose instead of contradicting.
      const reportedFindings = [...findings, ...suppressedFindings.map((s) => s.finding)];
      const payload = buildPayload({
        source, repo, commit, scanType, failOn, findings: reportedFindings, prComment,
        suppressed: {
          count: ignored + suppressedFindings.length,
          // Shape is `[{ rule, count }]` — the server drops anything else
          // (v1/appsec/scans validates defensively), so a plain string list was
          // silently discarded and the scan recorded a count with no attribution.
          // Same shape applyIgnore already produces, so the two merge cleanly.
          rules: [
            ...suppressedRules,
            ...Object.entries(
              suppressedFindings.reduce((acc, { rule }) => {
                const k = `${rule.matchType}:${rule.value}`;
                acc[k] = (acc[k] || 0) + 1;
                return acc;
              }, {}),
            ).map(([rule, count]) => ({ rule, count })),
          ],
        },
      });
      const res = await reportScan({ apiUrl, apiKey, payload });
      if (res.ok) io.error(`✓ Reported scan ${res.body?.scanId || ''} to ${apiUrl}`);
      else io.error(`⚠ Report failed (HTTP ${res.status}): ${res.body?.error || 'unknown error'}`);
    }
  }

  // PR/MR feedback (auto-detects GitHub / GitLab / Bitbucket from CI env).
  // Best-effort; never affects the exit code.
  if (flags['comment-pr']) {
    let reportUrl;
    const res = await postPrFeedback({ scope, findings, gate, reportUrl, log: (m) => io.error(m) });
    if (res?.skipped && output !== 'json') io.error(`⚠ --comment-pr: ${res.skipped}`);
  }

  // Exit code. ANY engine error means the scan is INCOMPLETE, so a passing gate would be a false
  // statement — not "nothing was found" but "we did not look". The old condition required EVERY
  // engine to fail before erroring, so one dead engine out of four still exited 0 on a repo with a
  // live token in it.
  if (errors.length) {
    if (output !== 'json') {
      io.error(`Scan incomplete — ${errors.length} engine(s) failed: ${errors.map((e) => e.engine).join(', ')}`);
      io.error('  A gate result is not meaningful when an engine did not run.');
    }
    return 2;
  }
  if (gate.blocked) return 1;
  return 0;
}

async function cmdDast(flags, restPositionals, io) {
  const target = flags.url || restPositionals[0];
  if (!target) {
    io.error('dast: --url <target> is required (the URL to actively scan).');
    return 2;
  }
  let url;
  try {
    url = new URL(target);
  } catch {
    io.error(`dast: invalid --url '${target}'.`);
    return 2;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    io.error('dast: --url must be http:// or https://.');
    return 2;
  }

  // Normalize case, and REJECT an unrecognized level instead of falling back.
  // A silent fallback to 'high' used to be harmless because 'high' was stricter
  // than most typos; with 'unknown' in the vocabulary it became a way to LOOSEN
  // the gate by mistyping — `--fail-on Unknown` passed a build with open
  // findings. A security gate must never quietly grade itself easier.
  const failOnRaw = flags['fail-on'];
  const failOn = failOnRaw === undefined ? 'high' : String(failOnRaw).toLowerCase();
  if (!FAIL_ON_LEVELS.includes(failOn)) {
    io.error(`Invalid --fail-on '${failOnRaw}'. Use one of: ${FAIL_ON_LEVELS.join(' | ')}`);
    return 2;
  }
  const output = flags.output === 'json' ? 'json' : 'rich';
  if (flags.mode && !['block', 'alert'].includes(flags.mode)) {
    io.error(`Invalid --mode '${flags.mode}'. Use: block | alert`); return 2;
  }
  const alertOnly = flags.mode === 'alert' || Boolean(flags['soft-fail']);
  const wantReport = flags['no-report'] ? false : (flags.report ?? false);
  const scanType = flags.diff ? 'diff' : 'full';
  const source = flags.source || 'ci-dast';

  // --tier is the primary interface (DAST = deep active scan; DAST Lite = fast
  // exposure scan). --engine is the back-compat alias (zap | nuclei). Default tier
  // is `deep` (DAST), matching the docs.
  let engine;
  if (flags.tier) {
    if (!['deep', 'lite'].includes(flags.tier)) {
      io.error(`dast: unknown --tier '${flags.tier}'. Use: deep | lite`); return 2;
    }
    engine = flags.tier === 'lite' ? 'nuclei' : 'zap';
  } else if (flags.engine) {
    if (!['nuclei', 'zap'].includes(flags.engine)) {
      io.error(`dast: unknown --engine '${flags.engine}'. Use: nuclei | zap`); return 2;
    }
    engine = flags.engine;
  } else {
    engine = 'zap'; // default tier = deep (DAST)
  }
  const tierLabel = engine === 'zap' ? 'DAST' : 'DAST Lite';

  if (output !== 'json') io.error(`Running ${tierLabel} scan against ${url.href} …`);
  let findings;
  try {
    if (engine === 'zap') {
      findings = await scanZap(url.href, { browser: Boolean(flags.browser), active: !flags.passive });
    } else {
      const opts = {};
      if (flags.severity) opts.severities = flags.severity;
      if (flags.templates) {
        opts.templates = flags.templates.split(',').map((s) => s.trim()).filter(Boolean);
      }
      findings = await scanDast(url.href, opts);
    }
  } catch (err) {
    io.error(`dast: scan failed — ${err.message}`);
    return 2;
  }
  if (output !== 'json') io.error(`  ${engine}: ${findings.length} finding(s)`);

  const gate = evaluateGate(findings, { failOn, softFail: alertOnly });
  io.log(renderResults({ findings, gate, errors: [], output }));

  if (flags.sarif) {
    await writeFile(flags.sarif, JSON.stringify(toSarif(findings, { version: VERSION }), null, 2));
    if (output !== 'json') io.error(`  wrote SARIF → ${flags.sarif}`);
  }

  // Report (opt-in). The platform authorizes by --url → a domain-verified,
  // ACTIVE DAST target; a non-owned/unverified URL is rejected (403). Report
  // failure never changes the local gate result.
  if (wantReport) {
    const { apiKey, apiUrl } = await resolveConfig(flags);
    if (!apiKey) {
      io.error('⚠ --report set but no API key found (set SHADOWSPAN_API_KEY or run `shadow-span auth`). Skipping upload.');
    } else {
      const payload = buildDastPayload({ source, targetUrl: url.href, scanType, failOn, findings });
      const res = await reportDastScan({ apiUrl, apiKey, payload });
      if (res.ok) io.error(`✓ Reported DAST scan ${res.body?.scanId || ''} to ${apiUrl}`);
      else io.error(`⚠ Report failed (HTTP ${res.status}): ${res.body?.error || 'unknown error'}`);
    }
  }

  if (gate.blocked) return 1;
  return 0;
}
