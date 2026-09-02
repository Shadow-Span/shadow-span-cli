import { describe, it, expect } from 'vitest';
import { buildSummary } from '../reporters/shared.js';
import { renderResults } from '../render.js';
import { evaluateGate } from '../../engine/src/gate.js';

/**
 * The PR comment must never state a count that contradicts the rows beneath it.
 *
 * WHAT WENT WRONG. PR gating scopes the GATE to the files a PR changed, deliberately — the scan
 * stays whole-repo and the report carries everything. But the comment took its severity counts from
 * `gate.bySeverity` (the changed-files subset) while building its table from `findings` (all of
 * them), with nothing saying they were different populations. On PR #87 that rendered as
 *
 *     🟠 5 high · 🟡 7 medium
 *
 * directly above a table containing 24 HIGH rows and "…and 237 more". A reader's only possible
 * conclusion is that the scanner cannot count. The same mismatch was in the terminal summary, the
 * Bitbucket Code Insights payload, and — worst — the JSON output, where `summary.total` (all) sat
 * beside `summary.bySeverity` (gated) in one object no consumer could interpret.
 *
 * These assert the INVARIANT (no unlabelled contradiction), not the wording, so a future rewrite of
 * the comment stays honest without having to remember this file.
 */

const f = (severity, file, type = 'SAST') => ({
  severity, file, type, ruleName: `${severity} in ${file}`, line: 1, status: 'OPEN',
});

// 10 findings, 8 HIGH. Only the 2 in `changed.js` are in the PR's diff.
const ALL = [
  f('HIGH', 'changed.js'), f('HIGH', 'changed.js'),
  f('HIGH', 'old-a.js'), f('HIGH', 'old-b.js'), f('HIGH', 'old-c.js'),
  f('HIGH', 'old-d.js'), f('HIGH', 'old-e.js'), f('HIGH', 'old-f.js'),
  f('MEDIUM', 'old-g.js'), f('LOW', 'old-h.js'),
];
const GATED = ALL.filter((x) => x.file === 'changed.js');

const gate = evaluateGate(GATED, { failOn: 'critical' });
const scope = {
  diffBase: 'origin/main',
  gatedCount: GATED.length,
  totalCount: ALL.length,
  totalBySeverity: evaluateGate(ALL, { failOn: 'none' }).bySeverity,
};

describe('PR summary — gated subset vs full finding set', () => {
  it('reports BOTH populations when the gate is diff-scoped', () => {
    const md = buildSummary({ findings: ALL, gate, scope });
    // 2 is what the gate judged; 8 is what the table shows. Both must appear.
    expect(md).toMatch(/\*\*2\*\* high/);
    expect(md).toMatch(/\*\*8\*\* high/);
  });

  it('labels which population each number describes', () => {
    const md = buildSummary({ findings: ALL, gate, scope });
    expect(md).toMatch(/changed files/i);
    expect(md).toMatch(/whole repositor/i);
  });

  /**
   * The regression itself. Before the fix the ONLY severity line was the gated one, so a comment
   * listing 8 HIGH rows announced "2 high" and nothing else. Asserting that the table's own HIGH
   * count is stated somewhere is the contract — it does not care how the comment is worded.
   */
  it('never shows a HIGH count that the table alone would contradict', () => {
    const md = buildSummary({ findings: ALL, gate, scope });
    const rowHighs = (md.match(/^\| 🟠 HIGH \|/gm) || []).length;
    expect(rowHighs).toBe(8);
    expect(md, `table shows ${rowHighs} HIGH rows but that count appears nowhere in the summary`)
      .toMatch(new RegExp(`\\*\\*${rowHighs}\\*\\* high`));
  });

  it('states that the table is the whole repository, not the gated subset', () => {
    expect(buildSummary({ findings: ALL, gate, scope })).toMatch(/not only the gated subset/i);
  });

  it('stays single-numbered when the gate was NOT scoped', () => {
    // Whole-tree run (--no-pr-gate, push, workflow_dispatch): one population, so two labelled lines
    // would be noise claiming a distinction that does not exist.
    const wholeGate = evaluateGate(ALL, { failOn: 'critical' });
    const md = buildSummary({ findings: ALL, gate: wholeGate });
    expect(md).toMatch(/\*\*8\*\* high/);
    expect(md).not.toMatch(/whole repositor/i);
    expect(md).not.toMatch(/changed files/i);
  });

  it('handles a scoped gate with zero findings in the diff', () => {
    // The common case on a docs-only PR. It must not read as "the repo is clean".
    const emptyGate = evaluateGate([], { failOn: 'critical' });
    const md = buildSummary({
      findings: ALL,
      gate: emptyGate,
      scope: { ...scope, gatedCount: 0 },
    });
    expect(md).toMatch(/\*\*8\*\* high/);       // the repo total is still stated
    expect(md).toMatch(/Gate passed/);
  });
});

describe('terminal + JSON output — same invariant', () => {
  it('json keeps summary and gate describing their own populations', () => {
    const out = JSON.parse(renderResults({ findings: ALL, gate, scope, output: 'json' }));
    expect(out.summary.total).toBe(10);
    expect(out.summary.bySeverity.HIGH).toBe(8);   // matches summary.total's population
    expect(out.gate.bySeverity.HIGH).toBe(2);      // the gated subset
    expect(out.gate.scoped).toBe(true);
    expect(out.gate.gatedCount).toBe(2);
  });

  it('terminal summary counts the findings it just listed', () => {
    // BOLD/DIM wrappers are emitted regardless of the colour flag, so strip ANSI: this asserts the
    // content of the summary, not its formatting.
    const strip = (t) => t.replace(/\u001b\[[0-9;]*m/g, '');
    const txt = strip(renderResults({ findings: ALL, gate, scope, output: 'rich', color: false }));
    expect(txt).toMatch(/Summary:\s*10 finding\(s\)/);
    expect(txt).toMatch(/8 high/);        // total, matching the listing
    expect(txt).toMatch(/Gate scope:/);   // and the gated view, labelled
    expect(txt).toMatch(/2 in changed files/);
  });
});
