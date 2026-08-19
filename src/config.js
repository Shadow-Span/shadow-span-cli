// CLI config — API key + endpoint resolution. Precedence (highest first):
//   1. explicit flag (--api-key / --api-url)
//   2. environment (SHADOWSPAN_API_KEY / SHADOWSPAN_API_URL)
//   3. config file (~/.config/shadowspan/config.json, chmod 600)
//
// The key is a write-only WRITE_APPSEC token. It is stored 0600 and never
// printed back. We do NOT support keys on argv in CI logs — prefer env.

import { homedir } from 'node:os';
import path from 'node:path';
import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';

export const DEFAULT_API_URL = 'https://app.shadowspan.com';

function configDir() {
  // XDG_CONFIG_HOME respected; falls back to ~/.config.
  const base = process.env.XDG_CONFIG_HOME || path.join(homedir(), '.config');
  return path.join(base, 'shadowspan');
}
function configPath() {
  return path.join(configDir(), 'config.json');
}

export async function readConfigFile() {
  try {
    return JSON.parse(await readFile(configPath(), 'utf8'));
  } catch {
    return {};
  }
}

export async function saveAuth({ apiKey, apiUrl }) {
  const dir = configDir();
  await mkdir(dir, { recursive: true });
  const existing = await readConfigFile();
  const next = { ...existing };
  if (apiKey) next.apiKey = apiKey;
  if (apiUrl) next.apiUrl = apiUrl;
  const file = configPath();
  await writeFile(file, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
  await chmod(file, 0o600).catch(() => {});
  return file;
}

/**
 * Resolve { apiKey, apiUrl } from flags → env → config file.
 * @param {object} flags  parsed CLI flags ({ 'api-key', 'api-url' })
 */
/**
 * Reject an api-url that would send the API key somewhere it must never go.
 *
 * The key is a bearer credential: whatever host `--api-url` names receives it verbatim in an
 * Authorization header. Without this check, `--api-url http://attacker.example` — from a
 * copy-pasted command, a poisoned CI variable, or a tampered config file — exfiltrates a
 * WRITE_APPSEC token in cleartext, and the user sees a normal-looking scan.
 *
 * http:// is allowed ONLY for loopback, where there is no network to intercept and where
 * self-hosted development genuinely needs it. Any other plaintext host is refused outright
 * rather than warned about: a warning in CI output is a warning nobody reads.
 */
export function assertSafeApiUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`Invalid --api-url: ${raw}`);
  }
  if (u.protocol === 'https:') return;
  // URL.hostname keeps the brackets on IPv6 literals ('[::1]'), so compare against both forms —
  // a bare '::1' comparison silently fails and rejects a legitimate loopback URL.
  const host = u.hostname;
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  if (u.protocol === 'http:' && loopback) return;
  throw new Error(
    `Refusing to send your API key over ${u.protocol}// to ${u.hostname}. ` +
    'Use https:// (http:// is permitted only for localhost).',
  );
}

export async function resolveConfig(flags = {}) {
  const file = await readConfigFile();
  const apiKey = flags['api-key'] || process.env.SHADOWSPAN_API_KEY || file.apiKey || null;
  const apiUrl = (flags['api-url'] || process.env.SHADOWSPAN_API_URL || file.apiUrl || DEFAULT_API_URL).replace(/\/+$/, '');
  // Checked on every resolve, not just when the flag is passed — the value can also arrive from
  // the environment or the on-disk config, and those are just as attacker-influencable.
  assertSafeApiUrl(apiUrl);
  return { apiKey, apiUrl };
}
