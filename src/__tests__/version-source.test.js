// `shadow-span version`, the --help banner and SARIF's tool.driver.version must all
// report the version this package actually IS.
//
// v0.2.0 shipped to npm printing "0.1.0": VERSION was a hardcoded constant that had
// to be updated in lockstep with package.json, and wasn't. Uploaded SARIF named the
// wrong scanner version, which is the kind of wrong that survives in someone's
// compliance evidence. Now derived from the manifest — this guards that it stays so.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { run } from '../cli.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function io() { const out = []; return { log: (m) => out.push(String(m)), error: () => {}, out }; }

describe('reported version', () => {
  it('`version` prints package.json’s version', async () => {
    const o = io();
    expect(await run(['version'], o)).toBe(0);
    expect(o.out.join('')).toContain(pkg.version);
  });

  it('the --help banner carries the same version', async () => {
    const o = io();
    await run(['help'], o);
    expect(o.out.join('\n')).toContain(`shadow-span v${pkg.version}`);
  });

  it('is DERIVED, not restated — no hardcoded semver literal', () => {
    // The bug was a literal. Assert the mechanism, since a literal that happens to
    // be correct today would pass both tests above and drift again tomorrow.
    const src = readFileSync(path.join(ROOT, 'src/cli.js'), 'utf8');
    expect(src).not.toMatch(/const VERSION = ['"]\d+\.\d+\.\d+['"]/);
    expect(src).toMatch(/package\.json['"]\)\.version/);
  });
});
