// Provider-agnostic PR/MR comment builders. PURE (no I/O) — unit-tested. Each
// SCM reporter (github/gitlab/bitbucket) renders these into its own API shape.

export const MARKER = '<!-- shadow-span-appsec -->';
export const SEV_EMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', UNKNOWN: '⚪' };
export const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const TYPE_LABEL = { SECRET: 'Secret', SCA: 'Dependency', SAST: 'Code', IAC: 'IaC', SBOM_VULN: 'SBOM' };

export function escapePipe(s) { return String(s || '').replace(/\|/g, '\\|').replace(/\n/g, ' '); }

/**
 * Markdown summary comment. Idempotent: carries MARKER so a reporter can
 * find-and-edit its prior comment instead of stacking duplicates on re-push.
 */
function severityLine(bySeverity) {
  return SEV_ORDER
    .filter((s) => bySeverity?.[s])
    .map((s) => `${SEV_EMOJI[s]} **${bySeverity[s]}** ${s.toLowerCase()}`)
    .join(' · ');
}

/**
 * @param {object} [opts.scope]  present only when the gate was diff-scoped. Carries the WHOLE-REPO
 *   counts, because `gate.bySeverity` describes the changed-files subset the gate judged while the
 *   table below lists everything. Reporting one number for both populations is what made this
 *   comment read "5 high" directly above a table of 24 HIGH rows.
 */
export function buildSummary({ findings, gate, reportUrl, scope } = {}) {
  const lines = [MARKER, '', '## 🛡️ Shadow Span AppSec'];
  if (!findings || findings.length === 0) {
    lines.push('', '✅ No findings. Gate passed.');
    return lines.join('\n');
  }

  if (scope) {
    // Two populations, each labelled with what it is and why it differs.
    lines.push('', `**In this PR's changed files** — what the gate judges: ${severityLine(gate?.bySeverity) || '_none_'}`);
    lines.push('', `**Whole repository** — ${scope.totalCount} finding(s): ${severityLine(scope.totalBySeverity)}`);
  } else {
    lines.push('', severityLine(gate?.bySeverity));
  }

  lines.push('', gate?.blocked
    ? `### ❌ Gate failed — ${gate.blockingCount} finding(s) at or above \`${gate.failOn}\``
    : `### ✅ Gate passed (\`fail-on: ${gate?.failOn}\`)`);

  const sorted = [...findings].sort((a, b) =>
    SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const top = sorted.slice(0, 50);
  // Say which set this is. It lists the whole repository, not the gated subset, and a reader who
  // assumes otherwise concludes the counts above are broken.
  lines.push('', scope
    ? `#### All findings in the repository (${sorted.length}) — not only the gated subset`
    : `#### Findings (${sorted.length})`);
  lines.push('', '| Severity | Type | Finding | Location |', '|---|---|---|---|');
  for (const f of top) {
    const loc = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ''}\`` : '—';
    lines.push(`| ${SEV_EMOJI[f.severity] || ''} ${f.severity} | ${TYPE_LABEL[f.type] || f.type} | ${escapePipe(f.ruleName)} | ${loc} |`);
  }
  if (sorted.length > top.length) lines.push('', `_…and ${sorted.length - top.length} more._`);
  if (reportUrl) lines.push('', `[View full report ↗](${reportUrl})`);
  return lines.join('\n');
}

/**
 * One markdown comment body per finding that has a file + line (for inline
 * placement). Capped. Provider-neutral; reporters attach the right anchor shape.
 * @returns {Array<{file:string, line:number, body:string}>}
 */
export function buildInlineComments({ findings, max = 50 } = {}) {
  const out = [];
  for (const f of findings || []) {
    if (!f.file || !f.line) continue;
    const body = [
      `${SEV_EMOJI[f.severity] || ''} **${f.severity} · ${TYPE_LABEL[f.type] || f.type}** — ${f.ruleName}`,
      '',
      f.description || '',
      f.remediation ? `\n**Remediation:** ${f.remediation}` : '',
      f.cwe ? `\n_${f.cwe}_` : '',
    ].filter(Boolean).join('\n');
    out.push({ file: f.file, line: f.line, body });
    if (out.length >= max) break;
  }
  return out;
}

// Back-compat alias (GitHub reporter historically called it reviewComments with
// a `path`/`side` shape; reporters adapt as needed).
export function buildReviewComments(opts) {
  return buildInlineComments(opts).map((c) => ({ path: c.file, line: c.line, side: 'RIGHT', body: c.body }));
}
