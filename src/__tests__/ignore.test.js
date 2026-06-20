import { describe, it, expect } from 'vitest';
import { parseIgnore, applyIgnore } from '../ignore.js';

describe('parseIgnore', () => {
  it('ignores blank lines and comments', () => {
    const m = parseIgnore('\n# a comment\n\n  # indented\n');
    expect(m.count).toBe(0);
    expect(m.test('anything.js')).toBe(false);
  });

  it('matches a directory and everything under it', () => {
    const m = parseIgnore('node_modules/');
    expect(m.test('node_modules/foo/bar.js')).toBe(true);
    expect(m.test('src/node_modules/x.js')).toBe(true); // unanchored → any depth
    expect(m.test('src/app.js')).toBe(false);
  });

  it('** matches across path segments', () => {
    const m = parseIgnore('**/__fixtures__/**');
    expect(m.test('engine/rules/__fixtures__/vuln.go')).toBe(true);
    expect(m.test('packages/x/__fixtures__/a/b/c.js')).toBe(true);
    expect(m.test('src/scan.js')).toBe(false);
  });

  it('* matches within a segment only', () => {
    const m = parseIgnore('*.test.js');
    expect(m.test('a.test.js')).toBe(true);
    expect(m.test('deep/path/a.test.js')).toBe(true);
    expect(m.test('a.test.jsx')).toBe(false);
    expect(m.test('atestjs')).toBe(false);
  });

  it('leading slash anchors at the repo root', () => {
    const m = parseIgnore('/dist/');
    expect(m.test('dist/out.js')).toBe(true);
    expect(m.test('packages/x/dist/out.js')).toBe(false); // not at root
  });

  it('negation re-includes (last match wins)', () => {
    const m = parseIgnore('**/__fixtures__/**\n!**/__fixtures__/keepme.js');
    expect(m.test('a/__fixtures__/vuln.js')).toBe(true);
    expect(m.test('a/__fixtures__/keepme.js')).toBe(false);
  });

  it('normalizes windows separators + ./ prefix', () => {
    const m = parseIgnore('src/');
    expect(m.test('src\\a\\b.js')).toBe(true);
    expect(m.test('./src/a.js')).toBe(true);
  });
});

describe('applyIgnore', () => {
  const F = (file) => ({ file, severity: 'HIGH', identityKey: file });

  it('drops ignored findings, keeps the rest, counts both', () => {
    const m = parseIgnore('**/__fixtures__/**\n');
    const { kept, ignored } = applyIgnore(
      [F('src/app.js'), F('rules/__fixtures__/vuln.py'), F('lib/x.js')],
      m,
    );
    expect(ignored).toBe(1);
    expect(kept.map((f) => f.file)).toEqual(['src/app.js', 'lib/x.js']);
  });

  it('always keeps repo-wide findings (no file)', () => {
    const m = parseIgnore('**/*');
    const { kept } = applyIgnore([{ severity: 'LOW', identityKey: 'repo-wide' }], m);
    expect(kept).toHaveLength(1);
  });
});
