// CI/CD pipeline posture engine — GitHub Actions workflow misconfiguration.
//
// Cycode/StepSecurity-class "pipeline security" checks, shifted left into the
// repo scan. Dependency-free + line-based on purpose: GHA security issues are
// almost all pattern-locatable, and a line-based pass gives us exact file+line
// for every finding (a YAML parse would lose line numbers). No new dependency,
// no network — the lowest-risk net-new engine.
//
// Scope (v1): GitHub Actions workflows under .github/workflows/*.{yml,yaml}.
// Six rules covering the documented high-impact classes:
//   CICD-001 script injection via untrusted ${{ }} in run: blocks   (HIGH, CWE-94)
//   CICD-002 pull_request_target + PR-head checkout (the lethal combo) (CRITICAL, CWE-94)
//   CICD-003 unpinned action (uses @tag/branch, not a 40-hex SHA)    (MEDIUM, CWE-1357)
//   CICD-004 broad workflow permissions (write-all)                  (HIGH,  CWE-272)
//   CICD-005 curl|wget piped to a shell in run:                      (HIGH,  CWE-494)
//   CICD-006 secret echoed to logs in run:                           (MEDIUM, CWE-532)
//
// GitLab CI / CircleCI / Jenkins are future additions (same line-based shape).

import { readdir, readFile, lstat } from 'node:fs/promises';
import path from 'node:path';

import { buildIdentityKey, FINDING_TYPES } from '../normalize.js';

const MAX_FILE_BYTES = 256 * 1024; // workflow files are tiny; cap defends against junk
const WORKFLOW_DIR = path.join('.github', 'workflows');

// Untrusted GitHub-context expressions that must never be interpolated directly
// into a shell `run:` — the canonical Actions script-injection vectors.
// (github.event.*.{title,body,...} + head_ref are attacker-controllable.)
const UNTRUSTED_EXPR =
  /\$\{\{\s*github\.(event\.[a-z_]*\.(title|body|message|name|email|ref|label|head_ref)|event\.(comment|issue|pull_request|review|review_comment)\.|head_ref|event\.head_commit\.message)/i;

// A pinned action ref is a 40-char hex commit SHA. Anything else (@v4, @main,
// @master, a semver tag) is mutable and a supply-chain risk.
const UNPINNED_USES = /^\s*-?\s*uses:\s*["']?([\w.-]+\/[\w.-]+)@([^\s"'#]+)/;
const SHA40 = /^[0-9a-f]{40}$/i;

const CURL_PIPE_SHELL = /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b/i;
const SECRET_ECHO = /\b(echo|printf)\b[^\n]*\$\{\{\s*secrets\./i;
const SECRETS_REF = /\$\{\{\s*secrets\./i;

const RULE_META = {
  'CICD-001': { name: 'Script injection — untrusted input in run step', severity: 'HIGH', cwe: 'CWE-94',
    remediation: 'Never interpolate ${{ github.event.* }} / github.head_ref directly into a run: shell. Pass it via an env: var and reference "$VAR" (quoted) instead.' },
  'CICD-002': { name: 'pull_request_target checks out untrusted PR code', severity: 'CRITICAL', cwe: 'CWE-94',
    remediation: 'pull_request_target runs with repo secrets. Do not check out and build PR-head code in it. Use pull_request, or checkout the base ref only.' },
  'CICD-003': { name: 'Unpinned GitHub Action (mutable ref)', severity: 'MEDIUM', cwe: 'CWE-1357',
    remediation: 'Pin third-party actions to a full 40-char commit SHA (e.g. uses: actions/checkout@<sha>) so a hijacked tag cannot inject code.' },
  'CICD-004': { name: 'Workflow grants write-all permissions', severity: 'HIGH', cwe: 'CWE-272',
    remediation: 'Replace permissions: write-all with the least-privilege set the workflow needs (e.g. contents: read).' },
  'CICD-005': { name: 'Remote script piped to a shell', severity: 'HIGH', cwe: 'CWE-494',
    remediation: 'Do not pipe curl/wget output straight to sh/bash. Download, verify a checksum/signature, then execute.' },
  'CICD-006': { name: 'Secret echoed to build logs', severity: 'MEDIUM', cwe: 'CWE-532',
    remediation: 'Never echo ${{ secrets.* }} — it lands in plaintext logs. Use the secret directly in the command or mask it.' },
};

function mkFinding(ruleId, file, line, snippet, extra = '') {
  const meta = RULE_META[ruleId];
  const finding = {
    type: FINDING_TYPES.CICD,
    ruleId,
    ruleName: meta.name,
    severity: meta.severity,
    file,
    line,
    column: null,
    description: `${meta.name} (${meta.cwe}).${extra ? ` ${extra}` : ''}`,
    remediation: meta.remediation,
    cveId: null,
    packageName: null,
    packageEcosystem: null,
    packageVersion: null,
    fixedVersion: null,
    cwe: meta.cwe,
    evidence: { engine: 'cicd-posture', rule: ruleId, snippet: (snippet || '').trim().slice(0, 300) },
  };
  finding.identityKey = buildIdentityKey(finding);
  return finding;
}

/**
 * Mark which line indices sit inside a `run:` block (block-scalar or inline).
 * Line-based heuristic: a `run:` key opens a block at its indent; deeper-indented
 * lines belong to it; the inline form (`run: cmd`) covers only its own line.
 */
function computeRunBlockLines(lines) {
  const inRun = new Array(lines.length).fill(false);
  let runIndent = -1;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim()) { if (runIndent >= 0) inRun[i] = true; continue; }
    const indent = raw.length - raw.trimStart().length;
    const runKey = raw.match(/^(\s*)(-\s+)?run:(\s*\|.*|\s*>.*|\s+\S.*)?$/);
    if (runKey) {
      const keyIndent = runKey[1].length + (runKey[2] ? runKey[2].length : 0);
      const rest = (runKey[3] || '').trim();
      inRun[i] = true; // the run: line itself (covers inline `run: cmd`)
      // Block scalar (| or >) → following deeper lines are in-block.
      runIndent = /^[|>]/.test(rest) || rest === '' ? keyIndent : -1;
      continue;
    }
    if (runIndent >= 0) {
      if (indent > runIndent) inRun[i] = true;
      else runIndent = -1;
    }
  }
  return inRun;
}

/** Scan a single workflow file's text → findings. */
export function scanWorkflowText(text, file) {
  const lines = text.split('\n');
  const inRun = computeRunBlockLines(lines);
  const findings = [];

  const hasPrTarget = /^on:|pull_request_target/m.test(text) && /\bpull_request_target\b/.test(text);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln = i + 1;

    // CICD-004 — write-all permissions (anywhere; workflow or job level).
    if (/^\s*permissions:\s*write-all\s*$/.test(line)) {
      findings.push(mkFinding('CICD-004', file, ln, line));
    }

    // CICD-003 — unpinned third-party action.
    const uses = line.match(UNPINNED_USES);
    if (uses) {
      const action = uses[1];
      const ref = uses[2];
      const isLocal = action.startsWith('.') || action.startsWith('docker://');
      // First-party actions/* and github/* are GitHub-maintained; still flag —
      // tag mutability is the risk regardless of owner — but note the owner.
      if (!isLocal && !SHA40.test(ref)) {
        findings.push(mkFinding('CICD-003', file, ln, line, `${action}@${ref} is not pinned to a commit SHA.`));
      }
    }

    // CICD-002 — pull_request_target workflow checking out PR-head code.
    if (hasPrTarget && /ref:\s*\$\{\{\s*github\.event\.(pull_request\.head|workflow_run\.head)/.test(line)) {
      findings.push(mkFinding('CICD-002', file, ln, line, 'Checking out PR-head in a pull_request_target run exposes repo secrets to attacker code.'));
    }

    // run-block-scoped rules.
    if (inRun[i]) {
      if (UNTRUSTED_EXPR.test(line)) {
        findings.push(mkFinding('CICD-001', file, ln, line));
      }
      if (CURL_PIPE_SHELL.test(line)) {
        findings.push(mkFinding('CICD-005', file, ln, line));
      }
      if (SECRET_ECHO.test(line) || (/\becho\b/.test(line) && SECRETS_REF.test(line))) {
        findings.push(mkFinding('CICD-006', file, ln, line));
      }
    }
  }

  return findings;
}

/**
 * Scan .github/workflows/*.{yml,yaml} under a checked-out repo.
 * @returns {Promise<Array>} normalized AppSecFinding rows (type=CICD)
 */
export async function scanCicd(repoPath) {
  const dir = path.join(repoPath, WORKFLOW_DIR);
  let entries;
  try {
    entries = await readdir(dir);
  } catch {
    return []; // no workflows directory — nothing to scan
  }

  const findings = [];
  for (const name of entries) {
    if (!/\.(ya?ml)$/i.test(name)) continue;
    const full = path.join(dir, name);
    try {
      const st = await lstat(full);
      if (!st.isFile() || st.size > MAX_FILE_BYTES) continue; // skip symlinks + oversized
      const text = await readFile(full, 'utf8');
      findings.push(...scanWorkflowText(text, path.join(WORKFLOW_DIR, name)));
    } catch (err) {
      console.warn(`[APPSEC] cicd: skipped ${name}: ${err.message}`);
    }
  }
  return findings;
}
