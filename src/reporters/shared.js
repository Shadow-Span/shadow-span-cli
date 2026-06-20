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
export function buildSummary({ findings, gate, reportUrl } = {}) {
  const lines = [MARKER, '', '## 🛡️ Shadow Span AppSec'];
  if (!findings || findings.length === 0) {
    lines.push('', '✅ No findings. Gate passed.');
    return lines.join('\n');
  }

  const counts = SEV_ORDER
    .filter((s) => gate?.bySeverity?.[s])
    .map((s) => `${SEV_EMOJI[s]} **${gate.bySeverity[s]}** ${s.toLowerCase()}`)
    .join(' · ');
  lines.push('', counts);

  lines.push('', gate?.blocked
    ? `### ❌ Gate failed — ${gate.blockingCount} finding(s) at or above \`${gate.failOn}\``
    : `### ✅ Gate passed (\`fail-on: ${gate?.failOn}\`)`);

  const sorted = [...findings].sort((a, b) =>
    SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const top = sorted.slice(0, 50);
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
