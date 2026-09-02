// fetchAppSecSettings — platform-managed suppression rules reaching the CLI.
//
// The contract that matters: a rule the SERVER says applies must be evaluable by
// the kernel on a CLI finding, and a malformed or hostile row must not become a
// rule that matches more than intended.
import { describe, it, expect, vi, afterEach } from 'vitest';

import { fetchAppSecSettings } from '../settings.js';
import { isSuppressed } from '../../engine/src/suppression.js';

const API = 'https://app.example.com';
const KEY = 'k';

function mockFetch(body, { ok = true } = {}) {
  const spy = vi.fn().mockResolvedValue({ ok, json: async () => body });
  vi.stubGlobal('fetch', spy);
  return spy;
}
afterEach(() => vi.unstubAllGlobals());

const rule = (over = {}) => ({
  matchType: 'RULE_ID', value: 'CVE-2026-1', scope: 'ORG',
  expiresAt: '2099-01-01T00:00:00.000Z', reason: 'accepted in the dashboard', ...over,
});
const finding = (over = {}) => ({ type: 'SCA', ruleId: 'CVE-2026-1', status: 'OPEN', ...over });

describe('fetchAppSecSettings — suppression rules', () => {
  it('sends repo identity so the server can resolve REPO-scoped rules', async () => {
    const spy = mockFetch({ suppressionRules: [] });
    await fetchAppSecSettings({
      apiUrl: API, apiKey: KEY, repo: { provider: 'GITHUB', owner: 'acme', name: 'api' },
    });
    const url = new URL(spy.mock.calls[0][0]);
    expect(url.pathname).toBe('/api/v1/appsec/settings');
    expect(url.searchParams.get('provider')).toBe('GITHUB');
    expect(url.searchParams.get('owner')).toBe('acme');
    expect(url.searchParams.get('name')).toBe('api');
  });

  it('omits repo params when there is no repo identity', async () => {
    const spy = mockFetch({ suppressionRules: [] });
    await fetchAppSecSettings({ apiUrl: API, apiKey: KEY, repo: null });
    expect(new URL(spy.mock.calls[0][0]).search).toBe('');
  });

  it('returns a rule the kernel can actually apply to a CLI finding', async () => {
    mockFetch({ suppressionRules: [rule()] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    expect(s.suppressionRules).toHaveLength(1);
    // The whole point: it must suppress. A CLI finding has NO repositoryId.
    expect(isSuppressed(finding(), s.suppressionRules)).toBe(true);
  });

  it('forces REPO-scoped rules to ORG so they are not silently inert', async () => {
    // findingMatchesRule() rejects a REPO rule whose repositoryId does not equal
    // the finding's — and a CLI finding has none, so an unconverted REPO rule
    // would never match while looking perfectly configured.
    mockFetch({ suppressionRules: [rule({ scope: 'REPO' })] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    expect(s.suppressionRules[0].scope).toBe('ORG');
    expect(s.suppressionRules[0].originScope).toBe('REPO');
    expect(isSuppressed(finding(), s.suppressionRules)).toBe(true);
  });

  it('marks platform rules so output can distinguish them from the repo file', async () => {
    mockFetch({ suppressionRules: [rule()] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    expect(s.suppressionRules[0].origin).toBe('platform');
  });

  it('honours a null expiry (platform rules may be permanent)', async () => {
    mockFetch({ suppressionRules: [rule({ expiresAt: null })] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    expect(s.suppressionRules[0].expiresAt).toBeNull();
    expect(isSuppressed(finding(), s.suppressionRules)).toBe(true);
  });

  it('drops an expired rule rather than applying it', async () => {
    mockFetch({ suppressionRules: [rule({ expiresAt: '2020-01-01T00:00:00.000Z' })] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    // Kept in the list but inactive — isRuleActive is the single decision point.
    expect(isSuppressed(finding(), s.suppressionRules)).toBe(false);
  });

  it.each([
    ['unknown matchType', rule({ matchType: 'VIBES' })],
    ['empty value', rule({ value: '   ' })],
    ['missing value', rule({ value: undefined })],
    ['unparsable expiry', rule({ expiresAt: 'soon' })],
    ['not an object', 'CVE-2026-1'],
  ])('rejects a malformed row (%s) instead of half-applying it', async (_n, bad) => {
    mockFetch({ suppressionRules: [bad] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    expect(s.suppressionRules).toEqual([]);
  });

  it('NEVER lets a platform rule suppress MALWARE', async () => {
    mockFetch({ suppressionRules: [rule({ matchType: 'FINDING_TYPE', value: 'MALWARE' })] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    const mal = finding({ type: 'MALWARE', ruleId: 'MAL-2026-1' });
    expect(isSuppressed(mal, s.suppressionRules)).toBe(false);
  });

  it('an old platform that omits the field yields no suppressions, not a crash', async () => {
    mockFetch({ secretAllowlist: [], pathExclusions: [] });
    const s = await fetchAppSecSettings({ apiUrl: API, apiKey: KEY });
    expect(s.suppressionRules).toEqual([]);
  });

  it('fails OPEN toward stricter — an unreachable platform means no suppressions', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    expect(await fetchAppSecSettings({ apiUrl: API, apiKey: KEY })).toBeNull();
  });

  it('a non-OK response yields null, never partial settings', async () => {
    mockFetch({ suppressionRules: [rule()] }, { ok: false });
    expect(await fetchAppSecSettings({ apiUrl: API, apiKey: KEY })).toBeNull();
  });
});
