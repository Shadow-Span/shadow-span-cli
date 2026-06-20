// Output rendering — our own format (never raw engine output). Two modes:
//   rich  — human-readable grouped summary (default, TTY)
//   json  — machine-readable { findings, gate, summary } for piping

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const SEV_COLOR = { CRITICAL: '\x1b[41m\x1b[37m', HIGH: '\x1b[31m', MEDIUM: '\x1b[33m', LOW: '\x1b[36m', UNKNOWN: '\x1b[90m' };
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function color(on, sev, text) {
  if (!on) return text;
  return `${SEV_COLOR[sev] || ''}${text}${RESET}`;
}

const TYPE_LABEL = { SECRET: 'Secret', SCA: 'Dependency', SAST: 'Code', IAC: 'IaC', SBOM_VULN: 'SBOM' };

/**
 * @param {object} args
 * @param {Array}  args.findings
 * @param {object} args.gate     from evaluateGate
 * @param {Array}  args.errors   engine errors
 * @param {string} args.output   'rich' | 'json'
 * @param {boolean} [args.color] colorize (default: stdout TTY)
 * @returns {string}
 */
export function renderResults({ findings, gate, errors = [], output = 'rich', color: useColor }) {
  if (output === 'json') {
    return JSON.stringify({ summary: { total: findings.length, bySeverity: gate.bySeverity }, gate, errors, findings }, null, 2);
  }

  const on = useColor ?? Boolean(process.stdout.isTTY);
  const lines = [];

  if (findings.length === 0) {
    lines.push(`${BOLD}✓ No findings.${RESET}`);
  } else {
    // Sort: severity desc, then type, then file.
    const sorted = [...findings].sort((a, b) =>
      SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) ||
      String(a.type).localeCompare(String(b.type)) ||
      String(a.file || '').localeCompare(String(b.file || '')));

    for (const f of sorted) {
      const sev = SEV_ORDER.includes(f.severity) ? f.severity : 'UNKNOWN';
      const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '(repo-wide)';
      const tag = color(on, sev, ` ${sev} `);
      const kind = TYPE_LABEL[f.type] || f.type;
      lines.push(`${tag} ${BOLD}${kind}${RESET} ${f.ruleName}`);
      lines.push(`${DIM}    ${loc}${RESET}`);
      if (f.packageName) lines.push(`${DIM}    package: ${f.packageName}@${f.packageVersion || '?'}${f.fixedVersion ? ` → fixed ${f.fixedVersion}` : ''}${RESET}`);
      if (f.description) lines.push(`${DIM}    ${truncate(f.description, 160)}${RESET}`);
    }
  }

  lines.push('');
  const counts = SEV_ORDER.filter((s) => gate.bySeverity[s]).map((s) => color(on, s, `${gate.bySeverity[s]} ${s.toLowerCase()}`)).join('  ');
  lines.push(`${BOLD}Summary:${RESET} ${findings.length} finding(s)${counts ? `  —  ${counts}` : ''}`);

  if (errors.length) {
    lines.push(`${SEV_COLOR.HIGH}⚠ ${errors.length} engine error(s):${RESET} ${errors.map((e) => e.engine).join(', ')}`);
  }

  if (gate.blocked) {
    lines.push(color(on, 'HIGH', `${BOLD}✗ Gate failed${RESET} — ${gate.blockingCount} finding(s) at or above '${gate.failOn}'.`));
  } else {
    lines.push(`${BOLD}✓ Gate passed${RESET} (fail-on: ${gate.failOn}).`);
  }

  return lines.join('\n');
}

function truncate(s, n) {
  s = String(s || '').replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
