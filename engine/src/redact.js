// Secret redactor — masks high-confidence credential token shapes in any text
// that might be stored or transmitted (SAST/IaC code-context windows, evidence
// strings). A SAST finding's ±N-line snippet can incidentally capture a secret
// sitting on an adjacent line; without this, that secret would ride into the
// platform DB and force the customer to rotate it.
//
// Design: HIGH-CONFIDENCE patterns only (specific prefixes / structures) to keep
// false positives near zero — we're masking inside source the customer DID send
// for context, so over-redaction only costs a little readability, but a missed
// secret is a real incident. The generic key=value rule is deliberately
// conservative (requires a credential-ish key name + a quoted/long value).

const MASK = '«REDACTED»';

// Each entry masks the matched credential. Ordered specific → generic.
const PATTERNS = [
  // Private key PEM blocks (any line of the block).
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,
  // GitHub tokens.
  /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  // OpenAI / Anthropic.
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-[A-Za-z0-9]{20,}\b/g,
  // AWS access key id (+ STS).
  /\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b/g,
  // Google API key.
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  // Slack tokens.
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  // GitLab PAT.
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  // JWT (three base64url segments).
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];

// Conservative generic credential assignment: keep the key, mask the value.
//   token = "abc123…"   api_key: 'x…'   password=hunter2longvalue
const GENERIC_ASSIGN = /\b(passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\b(\s*[:=]\s*|\s+)(['"]?)([^\s'"]{8,})\3/gi;

/**
 * Mask credential tokens in a string. Returns the input unchanged if no match.
 * @param {string} text
 * @returns {string}
 */
export function redactSecrets(text) {
  if (typeof text !== 'string' || !text) return text;
  let out = text;
  for (const re of PATTERNS) out = out.replace(re, MASK);
  out = out.replace(GENERIC_ASSIGN, (m, key, sep, q) => `${key}${sep}${q}${MASK}${q}`);
  return out;
}

/**
 * Redact a multi-line block WITHOUT changing how many lines it has.
 *
 * WHY THIS EXISTS. The PEM pattern spans a whole key block, so redacting a
 * code-context window line by line could never match it: only the
 * `-----BEGIN…-----` header line was masked and the base64 body — the actual
 * private key — passed through untouched and was uploaded in
 * `evidence.codeContext`. Found in a pre-release security review, 2026-09-02;
 * it contradicted the CLI's own promise that secret values never leave the
 * machine.
 *
 * Joining the window and calling redactSecrets() fixes the masking but breaks
 * the line numbering, because a multi-line match collapses to a single token and
 * every following line shifts. So each match keeps its newline count: the
 * credential is gone, the block still occupies the same lines, and the `n` /
 * `isMatch` mapping on either side stays correct.
 *
 * @param {string} text  a block of text (typically a joined code-context window)
 * @returns {string}     same line count, credentials masked
 */
export function redactSecretsPreservingLines(text) {
  if (typeof text !== 'string' || !text) return text;
  // Mark EVERY line of a multi-line match, not just the first. A code-context
  // window is a SLICE of the file, so a block whose mask landed on a line outside
  // the window rendered as blank lines — no leak, but a reviewer reading the
  // snippet sees nothing and cannot tell redaction from an empty file.
  const keepLines = (m) => {
    const newlines = (m.match(/\n/g) || []).length;
    return newlines ? Array(newlines + 1).fill(MASK).join('\n') : MASK;
  };
  let out = text;
  for (const re of PATTERNS) out = out.replace(re, keepLines);
  out = out.replace(GENERIC_ASSIGN, (m, key, sep, q) => `${key}${sep}${q}${MASK}${q}`);
  return out;
}

/**
 * Deep-redact every string in an arbitrary JSON-ish value (objects/arrays/strings).
 * Used server-side as defense-in-depth over untrusted evidence.
 */
export function redactDeep(value) {
  if (typeof value === 'string') return redactSecrets(value);
  if (Array.isArray(value)) return value.map(redactDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v);
    return out;
  }
  return value;
}

/**
 * Make untrusted text safe to print on ONE terminal line.
 *
 * A suppression `reason` is attacker-controlled — it comes from a file in the
 * scanned repo, or from a platform rule stored with only trim+slice. Printed
 * raw, a trailing carriage return plus padding overwrites the line just written,
 * and ANSI escapes can recolour or clear it: the single log line recording that a
 * finding was suppressed can be made to vanish from CI output. Found in a
 * pre-release security review, 2026-09-02. The server already strips control
 * characters on the way IN; nothing did on the way OUT.
 *
 * Control characters (including CR/LF/ESC) become spaces, and the result is
 * clipped, so one entry can never take over the log.
 */
export function sanitizeForLog(text, max = 300) {
  if (typeof text !== 'string') return '';
  // eslint-disable-next-line no-control-regex -- stripping control chars IS the point
  const flat = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max)}\u2026` : flat;
}

export const _MASK = MASK;
