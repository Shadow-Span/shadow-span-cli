// Code-context enrichment — reads ±N lines around a finding's location from the
// checked-out repo and attaches them to `evidence.codeContext`. This is the
// "show a clip of the code" half of the finding detail (the other half,
// `evidence.fix`, is computed purely in normalize.js).
//
// SECURITY: only call this for SAST + IaC findings. NEVER for SECRET findings —
// the surrounding lines would re-introduce the leaked credential the gitleaks
// normalizer is careful to strip.
//
// File reads are cached per scan so a file with many findings is read once.

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { redactSecrets } from './redact.js';

const DEFAULT_CONTEXT_LINES = 3;
const MAX_LINE_LEN = 200; // clip pathological minified lines

/**
 * Mutates each finding in place, adding `evidence.codeContext`:
 *   { startLine, endLine, lines: [{ n, text, isMatch }] }
 * Findings without a readable file/line are left unchanged.
 *
 * @param {Array} findings  normalized AppSecFinding rows (SAST or IaC)
 * @param {string} repoRoot absolute path of the checked-out repo
 */
export async function attachCodeContext(findings, repoRoot, { contextLines = DEFAULT_CONTEXT_LINES } = {}) {
  const cache = new Map(); // relPath -> string[] | null (null = unreadable)

  for (const f of findings || []) {
    if (!f || !f.file || !Number.isInteger(f.line) || f.line < 1) continue;

    let lines = cache.get(f.file);
    if (lines === undefined) {
      try {
        const abs = path.resolve(repoRoot, f.file);
        // Defense-in-depth: never read outside the repo root.
        if (!abs.startsWith(path.resolve(repoRoot))) {
          lines = null;
        } else {
          lines = (await readFile(abs, 'utf8')).split(/\r?\n/);
        }
      } catch {
        lines = null;
      }
      cache.set(f.file, lines);
    }
    if (!lines) continue;

    const matchStart = f.line;
    const matchEnd = Math.max(matchStart, Number.isInteger(f.evidence?.endLine) ? f.evidence.endLine : matchStart);
    const from = Math.max(1, matchStart - contextLines);
    const to = Math.min(lines.length, matchEnd + contextLines);

    const window = [];
    for (let n = from; n <= to; n++) {
      const raw = lines[n - 1] ?? '';
      // Redact any credential sitting in the surrounding lines BEFORE it becomes
      // part of the finding — a secret adjacent to a SAST/IaC hit must never ride
      // into the snippet we store/transmit (the secret-rotation rule).
      const text = redactSecrets(raw);
      window.push({
        n,
        text: text.length > MAX_LINE_LEN ? `${text.slice(0, MAX_LINE_LEN)}…` : text,
        isMatch: n >= matchStart && n <= matchEnd,
      });
    }

    f.evidence = { ...(f.evidence || {}), codeContext: { startLine: from, endLine: to, lines: window } };
  }
  return findings;
}
