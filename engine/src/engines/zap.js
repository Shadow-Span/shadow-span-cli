// OWASP ZAP DAST engine (active + passive). Shells out to `zap.sh` (the ZAP
// install) on PATH or at ZAP_PATH — present only in the ZAP Docker images
// (services/appsec/Dockerfile.zap{,-browser} + the appsec-zap-scan Action), NOT
// in the repo-scan image or the CLI host. Gracefully returns [] if ZAP is
// absent, mirroring scanDast (nuclei).
//
// Browser tier (opts.browser): uses the AJAX spider (Chrome) to crawl SPAs. The
// ZAP browser image bakes --no-sandbox into Chrome at the canonical binary path,
// so NO chrome flags are needed here — the engine is identical either way.
//
// SAFETY: ZAP active scanning is intrusive — only ever invoked for an authorized,
// domain-verified target (the dast-runner / ingest gate enforces this). The URL
// is validated + normalized here before it reaches the automation plan, so a
// malicious target string can't inject YAML or shell args.

import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { scannerEnv } from '../lib/scanner-env.js';

import { normalizeZapResults } from '../normalize.js';

const execFileAsync = promisify(execFile);

const ZAP_BIN = process.env.ZAP_PATH || 'zap.sh';
// Whole-scan wall clock (spider + active). Active scanning is slow; default 20m,
// override for big apps / tight CI windows.
const ZAP_WALL_CLOCK_MS = Math.max(60_000, Number(process.env.APPSEC_ZAP_WALL_CLOCK_MS) || 20 * 60 * 1000);

export async function isZapAvailable() {
  try {
    await execFileAsync(ZAP_BIN, ['-version'], { env: scannerEnv(), timeout: 15_000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Build the ZAP automation-framework plan (YAML) for a scan. Pure + exported so
 * the discovery-strategy branches are unit-testable without a live ZAP.
 *   - opts.apiSpec { format: openapi|graphql|soap, url } → import the spec (no crawl)
 *   - opts.browser → AJAX spider (Chrome, SPA) instead of the traditional spider
 *   - opts.active=false → passive baseline only (no activeScan)
 * @param {string} safeUrl  already-validated http(s) URL
 */
export function buildZapPlan(safeUrl, opts = {}, { reportDir = '.', reportName = 'zap' } = {}) {
  const browser = Boolean(opts.browser);
  const active = opts.active !== false;
  const maxSpiderMins = clampInt(opts.maxSpiderMins, 1, 30, 3);
  const maxScanMins = clampInt(opts.maxScanMins, 1, 60, 10);
  const apiSpec = opts.apiSpec && opts.apiSpec.url ? opts.apiSpec : null;

  // Discovery: spec import (API) OR crawl (WEB_APP). AJAX spider needs Chrome —
  // only valid on the browser image; the trigger routes spaMode there.
  let discoveryJob;
  if (apiSpec) {
    let su;
    try { su = new URL(apiSpec.url); } catch { throw new Error(`buildZapPlan: invalid apiSpec.url: ${apiSpec.url}`); }
    if (su.protocol !== 'http:' && su.protocol !== 'https:') throw new Error('buildZapPlan: apiSpec.url must be http:// or https://');
    const safeSpec = su.href;
    const fmt = String(apiSpec.format || 'openapi').toLowerCase();
    if (fmt === 'graphql') {
      discoveryJob = `  - type: graphql
    parameters: { endpoint: "${safeUrl}", schemaUrl: "${safeSpec}" }`;
    } else if (fmt === 'soap') {
      discoveryJob = `  - type: soap
    parameters: { wsdlUrl: "${safeSpec}" }`;
    } else {
      discoveryJob = `  - type: openapi
    parameters: { apiUrl: "${safeSpec}", targetUrl: "${safeUrl}", context: ctx }`;
    }
  } else {
    discoveryJob = browser
      ? `  - type: spiderAjax
    parameters: { context: ctx, url: "${safeUrl}", maxDuration: ${maxSpiderMins}, browserId: chrome-headless, numberOfBrowsers: 2 }`
      : `  - type: spider
    parameters: { context: ctx, url: "${safeUrl}", maxDuration: ${maxSpiderMins} }`;
  }
  const activeJob = active
    ? `  - type: activeScan
    parameters: { context: ctx, maxScanDurationInMins: ${maxScanMins}, policy: "Default Policy" }`
    : '';

  return `env:
  contexts:
    - name: ctx
      urls: [ "${safeUrl}" ]
  parameters: { failOnError: false, failOnWarning: false, progressToStdout: true }
jobs:
${discoveryJob}
  - type: passiveScan-wait
    parameters: { maxDuration: 5 }
${activeJob ? activeJob + '\n' : ''}  - type: report
    parameters: { template: traditional-json, reportDir: "${reportDir}", reportFile: "${reportName}" }
`;
}

/**
 * Active (or passive) DAST scan of a running app with OWASP ZAP.
 * @param {string} targetUrl  http(s) URL to scan (must be authorized/owned)
 * @param {object} [opts]
 * @param {boolean} [opts.browser=false]  AJAX spider (Chrome) for SPAs — needs the browser image
 * @param {boolean} [opts.active=true]    run the active scanner (injection). false = passive baseline only
 * @param {object}  [opts.apiSpec]        API target: { format: 'openapi'|'graphql'|'soap', url } — import the spec instead of crawling
 * @param {number}  [opts.maxSpiderMins=3]
 * @param {number}  [opts.maxScanMins=10]
 * @returns {Promise<Array>} normalized type=DAST findings
 */
export async function scanZap(targetUrl, opts = {}) {
  // Validate + normalize the URL — `u.href` percent-encodes quotes/spaces, so the
  // value is safe to interpolate into the YAML plan.
  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    throw new Error(`scanZap: invalid URL: ${targetUrl}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('scanZap: URL must be http:// or https://');
  }
  const safeUrl = u.href;

  const workDir = await mkdtemp(path.join(tmpdir(), 'appsec-zap-'));
  const planPath = path.join(workDir, 'plan.yaml');
  const reportName = 'zap';
  const reportPath = path.join(workDir, `${reportName}.json`);

  const plan = buildZapPlan(safeUrl, opts, { reportDir: workDir, reportName });

  try {
    await writeFile(planPath, plan, 'utf8');
    try {
      await execFileAsync(ZAP_BIN, ['-cmd', '-autorun', planPath], {
        env: scannerEnv(), timeout: ZAP_WALL_CLOCK_MS,
        maxBuffer: 64 * 1024 * 1024,
      });
    } catch (err) {
      if (err.code === 'ENOENT') return []; // ZAP not installed — graceful, mirrors nuclei
      // A timeout or non-zero exit may still leave a partial report — fall through.
    }
    let raw = '';
    try {
      raw = await readFile(reportPath, 'utf8');
    } catch {
      return []; // no report at all
    }
    let report;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }
    return normalizeZapResults(report, { target: safeUrl });
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

function clampInt(v, min, max, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.round(n)));
}
