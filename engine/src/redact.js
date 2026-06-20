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

export const _MASK = MASK;
