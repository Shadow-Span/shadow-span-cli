// Pointing --api-url at the MARKETING host instead of the app host.
//
// Found while testing --report against dev (2026-09-02). `dev.shadowspan.com`
// 301s to `devapp.shadowspan.com` (the marketing-host → app-host redirect in
// proxy.js). Following that redirect breaks the request twice over: `fetch`
// strips the Authorization header across origins, and a 301 rewrites POST to
// GET. What the user saw was `HTTP 405: unknown error` on the report and a
// silent 401 on the settings fetch — neither of which names the actual mistake,
// which is a one-word difference in a hostname.
//
// So redirects are NOT followed; they are reported, naming the host to use.
import { describe, it, expect, vi, afterEach } from 'vitest';

import { reportScan } from '../report.js';
import { fetchAppSecSettings } from '../settings.js';

const redirectTo = (location) => vi.fn().mockResolvedValue({
  status: 301, ok: false,
  headers: { get: (h) => (h.toLowerCase() === 'location' ? location : null) },
  json: async () => ({}),
});
afterEach(() => vi.unstubAllGlobals());

describe('--api-url pointing at a redirecting host', () => {
  it('reportScan does not follow the redirect', async () => {
    const spy = redirectTo('https://app.example.com/api/v1/appsec/scans');
    vi.stubGlobal('fetch', spy);
    await reportScan({ apiUrl: 'https://example.com', apiKey: 'k', payload: {} });
    expect(spy.mock.calls[0][1].redirect).toBe('manual');
  });

  it('reportScan fails with a message naming the correct host', async () => {
    vi.stubGlobal('fetch', redirectTo('https://app.example.com/api/v1/appsec/scans'));
    const res = await reportScan({ apiUrl: 'https://example.com', apiKey: 'k', payload: {} });
    expect(res.ok).toBe(false);
    expect(res.body.error).toContain('https://app.example.com');
    // The reason matters as much as the host — otherwise it reads as a server bug.
    expect(res.body.error).toMatch(/credentials are not carried across a redirect/);
  });

  it('resolves a RELATIVE Location header to an absolute origin', async () => {
    vi.stubGlobal('fetch', redirectTo('/api/v1/appsec/scans'));
    const res = await reportScan({ apiUrl: 'https://example.com', apiKey: 'k', payload: {} });
    expect(res.body.error).toContain('https://example.com');
  });

  it('settings fetch does not follow it either, and returns null', async () => {
    const spy = redirectTo('https://app.example.com/api/v1/appsec/settings');
    vi.stubGlobal('fetch', spy);
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const out = await fetchAppSecSettings({ apiUrl: 'https://example.com', apiKey: 'k' });
    expect(spy.mock.calls[0][1].redirect).toBe('manual');
    // null, not a partial object — the caller then proceeds with NO org settings,
    // which makes the gate stricter rather than laxer.
    expect(out).toBeNull();
    expect(err.mock.calls.flat().join('')).toContain('app.example.com');
    err.mockRestore();
  });

  it('a normal 2xx response is unaffected', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      status: 200, ok: true, headers: { get: () => null },
      json: async () => ({ secretAllowlist: [], pathExclusions: [], suppressionRules: [] }),
    }));
    const out = await fetchAppSecSettings({ apiUrl: 'https://app.example.com', apiKey: 'k' });
    expect(out).toMatchObject({ secretAllowlist: [], pathExclusions: [], suppressionRules: [] });
  });
});
