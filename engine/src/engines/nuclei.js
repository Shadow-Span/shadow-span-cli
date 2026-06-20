// DAST engine — Nuclei (MIT, ProjectDiscovery). Phase 1 of the DAST plan
//. Template-driven detection of a RUNNING web app:
// CVEs, exposures, misconfigurations, default logins, tech fingerprints.
//
// Phase 1 is SAFE DETECTION ONLY — attack/fuzz tags are excluded (`-etags`),
// and Nuclei's default templates are non-destructive detection. ACTIVE
// (attack-payload) scanning is Phase 3 (OWASP ZAP), gated behind the
// AppSecDastTarget authorization + domain-ownership record.
//
// CLI (v3.x): nuclei -u <url> -jsonl -o <file> -etags <unsafe> -silent
// Exit codes: Nuclei writes JSONL incrementally, so even on a non-zero exit or
// our wall-clock timeout we parse whatever was written (partial results are
// valid). Only a missing report AND a hard exec error is a real failure.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { normalizeNucleiResults } from '../normalize.js';

const execFileAsync = promisify(execFile);

// Hard wall-clock cap for one target (default 15 min). The job-level timeout is
// longer; this bounds a single hung target.
const NUCLEI_TIMEOUT_MS = parseInt(process.env.APPSEC_NUCLEI_TIMEOUT_MS || `${15 * 60 * 1000}`, 10);

// Phase 1 safety: never run these template classes (attack / destructive).
const SAFE_EXCLUDE_TAGS = (process.env.APPSEC_NUCLEI_EXCLUDE_TAGS || 'dos,fuzz,intrusive,brute-force')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// Curated Phase-1 DETECTION profile. Running ALL ~13k Nuclei templates per
// target is far too slow, so when the caller doesn't pin templates (opts) and
// the APPSEC_NUCLEI_TEMPLATES env override isn't set, we scope to this
// high-signal set of template dirs instead of falling back to the full set.
const DEFAULT_TEMPLATES = [
  'http/exposures/',
  'http/misconfiguration/',
  'http/default-logins/',
  'http/exposed-panels/',
  'http/takeovers/',
  'ssl/',
  'http/technologies/',
];

// Absolute base dir of the baked nuclei-templates set (set in the scanner image
// Dockerfile / job env, e.g. /opt/nuclei-templates). When set, relative template
// dirs above are resolved against it so `-t` gets absolute paths — deterministic,
// independent of nuclei's own config-file template-directory resolution. Unset
// locally, where nuclei finds its templates dir on its own.
const TEMPLATE_BASE = process.env.APPSEC_NUCLEI_TEMPLATE_BASE || '';

/**
 * Run Nuclei against a single running-app target URL.
 * @param {string} targetUrl  e.g. https://app.example.com
 * @param {object} [opts]
 * @param {string[]} [opts.templates]   `-t` dirs/files (default: full template set)
 * @param {string}   [opts.severities]  `-severity` CSV (default: all)
 * @param {number}   [opts.rateLimitRps]
 * @param {number}   [opts.concurrency]
 * @param {number}   [opts.requestTimeoutSec]
 * @returns {Promise<Array>} normalized AppSecFinding-shaped rows (type=DAST)
 */
export async function scanDast(targetUrl, opts = {}) {
  const workDir = await mkdtemp(path.join(tmpdir(), 'appsec-nuclei-'));
  const reportPath = path.join(workDir, 'nuclei.jsonl');
  try {
    const args = [
      '-u', targetUrl,
      '-jsonl', '-o', reportPath,
      '-etags', SAFE_EXCLUDE_TAGS.join(','),
      '-timeout', String(opts.requestTimeoutSec || 10),
      '-retries', '1',
      '-rate-limit', String(opts.rateLimitRps || 40),
      '-concurrency', String(opts.concurrency || 25),
      '-disable-update-check',
      '-ni', // no interactsh — Phase-1 detection is response-based, no OOB callbacks
      '-no-color',
      '-silent',
    ];
    const envTemplates = (process.env.APPSEC_NUCLEI_TEMPLATES || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    // Precedence: explicit opts.templates → env override → curated default profile.
    const templates =
      opts.templates ||
      (envTemplates.length ? envTemplates : DEFAULT_TEMPLATES);
    // Resolve relative template dirs against the baked template base (prod
    // image sets APPSEC_NUCLEI_TEMPLATE_BASE=/opt/nuclei-templates). Absolute
    // paths and explicit opts/env values pass through untouched.
    const resolved = templates.map((t) =>
      TEMPLATE_BASE && !path.isAbsolute(t) ? path.join(TEMPLATE_BASE, t) : t,
    );
    for (const t of resolved) args.push('-t', t);
    if (opts.severities) args.push('-severity', opts.severities);

    let execError = null;
    try {
      await execFileAsync('nuclei', args, {
        timeout: NUCLEI_TIMEOUT_MS,
        maxBuffer: 32 * 1024 * 1024,
      });
    } catch (err) {
      execError = err; // partial report may still exist — fall through to read it
    }

    let raw = '';
    try {
      raw = await readFile(reportPath, 'utf8');
    } catch {
      // No report file at all + a hard exec error = a real failure.
      if (execError) {
        throw new Error(`nuclei failed (code=${execError.code}): ${truncate(execError.stderr || execError.message)}`);
      }
      raw = '';
    }

    const records = raw
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    return normalizeNucleiResults(records, { target: targetUrl });
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

function truncate(s, max = 500) {
  return String(s || '').slice(0, max);
}
