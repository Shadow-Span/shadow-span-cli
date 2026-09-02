// Repo-local suppression file — `.shadowspan-suppressions.json`.
//
// The platform stores suppression rules as AppSecSuppressionRule rows, but a CLI
// run in someone's CI has no database. Before this existed the only local lever
// was `.shadowspanignore`, which excludes by PATH — far too blunt for the case it
// kept getting used for: "this ONE advisory has no fix and does not affect us."
// Excluding the manifest to silence one advisory blinds the scan to every other
// advisory in that manifest, which is how a path-exclusion quietly becomes a
// coverage hole. This file suppresses a specific FINDING, and nothing else.
//
// The shape is the platform's own rule shape (matchType / value / scope), so a
// rule reads the same locally and server-side, and the same `isSuppressed()`
// kernel decides both.
//
// Two properties make this safe to hand a customer:
//   * `expiresAt` is MANDATORY — a suppression cannot become permanent by
//     neglect. An expired rule simply stops matching (isRuleActive), so the
//     finding blocks again on its own. Fail-closed by construction.
//   * MALWARE is unsuppressible inside the kernel, so no entry here can hide a
//     hostile package, whatever it claims to match.
//
// Format:
//   {
//     "suppressions": [
//       { "matchType": "RULE_ID", "value": "GO-2026-5932",
//         "expiresAt": "2027-03-01",
//         "reason": "why this does not affect us — required, and read by humans",
//         "upstream": "https://... (optional link to the advisory / upstream issue)" }
//     ]
//   }

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { isRuleActive, isSuppressed } from './suppression.js';
import { sanitizeForLog } from './redact.js';

export const SUPPRESSION_FILENAME = '.shadowspan-suppressions.json';

// A DELIBERATELY NARROWER VOCABULARY THAN THE PLATFORM'S.
//
// The platform supports all six SUPPRESSION_MATCH_TYPES because a dashboard rule
// is created by an authenticated analyst and carries an audit trail. This file is
// different in kind: it is committed by anyone who can open a pull request, and it
// is read by a gate whose whole job is to stop that pull request.
//
// Breadth is the danger, not the mechanism. With the full vocabulary, ONE entry —
// `{matchType:'PATH_GLOB', value:'**'}` — suppresses every non-MALWARE finding in
// the repository, and `FINDING_TYPE:'SECRET'` silences the entire secrets engine.
// Both validate cleanly and both look like ordinary config in a diff. So the file
// is limited to match types that name ONE THING: a specific advisory, or a
// specific package.
//
// CWE IS DELIBERATELY EXCLUDED, and it was in the first version of this list. A
// CWE names a weakness CLASS, not a finding, and our own normalizer stamps
// `cwe: 'CWE-798'` on EVERY gitleaks result (normalize.js) — so one entry reading
// `{matchType:'CWE', value:'CWE-798'}` silences the entire secrets engine while
// looking like a narrow, reasoned exception in a diff. `CWE-79` does the same to
// XSS results. That is precisely the breadth this list exists to prevent, so the
// rule is: a match type belongs here only if one entry can silence one finding.
//
// Path-based exclusion is not lost — it belongs in .shadowspanignore, which exists
// for exactly that, and whose drop counts are reported to the platform so it cannot
// become a silent channel.
export const FILE_MATCH_TYPES = Object.freeze(['RULE_ID', 'PACKAGE']);

// An expiry far enough out is a permanent exception wearing a date. `9999-12-31`
// passed every other check. Bounded HERE, in the kernel, so every consumer of the
// file gets the ceiling — not only the repo whose wrapper happens to check it.
export const MAX_EXPIRY_DAYS = 365;

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Parse + validate the file's text. Pure — no I/O, so it is fully testable.
 *
 * Malformed entries are ERRORS, not warnings: a config we cannot read must not
 * be reported as "no suppressions configured", or a typo in a rule someone
 * believes is protecting them passes silently.
 *
 * @returns {{ rules: Array, errors: string[], warnings: string[] }}
 */
export function parseSuppressionFile(text, { now = new Date(), filename = SUPPRESSION_FILENAME } = {}) {
  const errors = [];
  const warnings = [];
  const rules = [];

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { rules: [], errors: [`${filename} is not valid JSON: ${e.message}`], warnings };
  }

  const list = parsed?.suppressions;
  if (list === undefined) return { rules: [], errors: [`${filename}: missing "suppressions" array`], warnings };
  if (!Array.isArray(list)) return { rules: [], errors: [`${filename}: "suppressions" must be an array`], warnings };

  list.forEach((entry, i) => {
    const at = `${filename}: suppressions[${i}]`;
    if (!entry || typeof entry !== 'object') { errors.push(`${at} must be an object`); return; }

    if (!FILE_MATCH_TYPES.includes(entry.matchType)) {
      errors.push(
        `${at}.matchType must be one of ${FILE_MATCH_TYPES.join(' | ')} — each names ONE finding. `
        + 'Broad types (PATH_GLOB, FINDING_TYPE, ECOSYSTEM, CWE) are rejected here because a single entry '
        + 'would silence a whole class of findings; use .shadowspanignore for path exclusions, or an '
        + 'org suppression rule in the platform, where the decision is attributable and audited.',
      );
      return;
    }
    for (const k of ['value', 'reason', 'expiresAt']) {
      if (typeof entry[k] !== 'string' || !entry[k].trim()) { errors.push(`${at} is missing "${k}"`); return; }
    }
    if (!DATE_RE.test(entry.expiresAt)) { errors.push(`${at}.expiresAt must be YYYY-MM-DD`); return; }

    // End-of-day, so a rule stays valid through the whole of its final date
    // rather than lapsing at midnight UTC in the middle of someone's workday.
    // Parsed BEFORE the horizon comparison: that comparison is lexical, and
    // '2027-13-45' sorts after a real date, so checking it first reported an
    // impossible date as "too far in the future".
    const expiresAt = new Date(`${entry.expiresAt}T23:59:59.999Z`);
    if (Number.isNaN(expiresAt.getTime())) { errors.push(`${at}.expiresAt is not a real date`); return; }

    const horizon = new Date(now.getTime() + MAX_EXPIRY_DAYS * 864e5).toISOString().slice(0, 10);
    if (entry.expiresAt > horizon) {
      errors.push(
        `${at}.expiresAt is ${sanitizeForLog(entry.expiresAt, 40)}, beyond the ${MAX_EXPIRY_DAYS}-day maximum (${horizon}). `
        + 'A far-future expiry is a permanent exception with a date on it — shorten it and revisit.',
      );
      return;
    }
    if (entry.upstream !== undefined && !/^https?:\/\//.test(String(entry.upstream))) {
      errors.push(`${at}.upstream must be an http(s) URL when present`);
      return;
    }

    // Fields are copied EXPLICITLY, never spread from `entry`. A spread let the
    // file set any property it liked — including `origin: 'platform'`, which made
    // a repo-local acceptance print as a platform-managed one AND suppressed the
    // "matches nothing" warning that only applies to file rules. A committed file
    // must not be able to claim provenance it does not have.
    const rule = {
      scope: 'ORG',
      matchType: entry.matchType,
      value: entry.value,
      reason: entry.reason,
      ...(entry.upstream ? { upstream: entry.upstream } : {}),
      expiresAt,
      // Keep the literal for messages — re-deriving it from the Date reintroduces
      // a timezone question that has no reason to exist.
      expiresOn: entry.expiresAt,
      origin: 'file',
    };

    // Expired is deliberately NOT an error: the rule just stops matching, the
    // finding blocks again, and the warning says why. That is fail-closed, and
    // it means a stale file degrades to "no suppression" rather than to a crash.
    if (!isRuleActive(rule, now)) {
      // entry.value is attacker-controlled — a CR here would overwrite this very
      // warning line in a CI log, hiding that a suppression lapsed.
      warnings.push(`${at}: expired on ${entry.expiresAt} — no longer suppressing ${sanitizeForLog(entry.value, 100)}`);
    }
    rules.push(rule);
  });

  return { rules, errors, warnings };
}

/**
 * Read `.shadowspan-suppressions.json` from a repo root. An absent file is the
 * normal case, not an error.
 */
export async function loadSuppressionFile(repoPath, { now = new Date() } = {}) {
  const file = path.join(repoPath, SUPPRESSION_FILENAME);
  let text;
  try {
    text = await readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return { rules: [], errors: [], warnings: [], present: false };
    return { rules: [], errors: [`${SUPPRESSION_FILENAME} could not be read: ${e.message}`], warnings: [], present: true };
  }
  return { ...parseSuppressionFile(text, { now }), present: true };
}

/**
 * Split findings into those a rule suppresses and those that stand. Suppression
 * happens BEFORE gating, so a suppressed finding is reported but never blocks.
 *
 * @returns {{ kept: Array, suppressed: Array, unusedRules: Array }}
 */
export function applySuppressions(findings = [], rules = [], now = new Date()) {
  if (!rules.length) return { kept: findings, suppressed: [], unusedRules: [] };

  const kept = [];
  const suppressed = [];
  const used = new Set();

  for (const f of findings) {
    // Attribute the hit to a rule so the report can say WHICH one, and so an
    // unused rule can be flagged. isSuppressed() is the same kernel the server
    // uses — MALWARE is refused inside it.
    const rule = rules.find((r) => isSuppressed(f, [r], now));
    if (rule) { used.add(rule); suppressed.push({ finding: f, rule }); } else { kept.push(f); }
  }

  // An active rule matching nothing is dead weight that will silently start
  // matching something else later — surface it rather than let it accumulate.
  const unusedRules = rules.filter((r) => !used.has(r) && isRuleActive(r, now));
  return { kept, suppressed, unusedRules };
}
