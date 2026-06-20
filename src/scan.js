// Run the local engines over a checkout and collect normalized findings.
// Engines live in the VENDORED kernel at ./engine (a verbatim copy of the
// platform's the Shadow Span AppSec engine, kept in sync by
// the sync tooling). Vendored — not a workspace dep — so this
// CLI is self-contained and can be lifted into its own public repo. They shell
// out to the engine binaries on PATH (gitleaks / ast-grep / osv-scanner / trivy).

import { scanSecrets, scanSca, scanSast, scanIac } from '../engine/src/index.js';

export const ENGINE_RUNNERS = Object.freeze({
  secret: scanSecrets,
  sca: scanSca,
  sast: scanSast,
  iac: scanIac,
});

// CI default = full sweep. Pre-commit/--staged fast path = secrets + SAST only
// (the slow dependency/IaC scans belong in CI, not on every commit).
export const ALL_ENGINES = Object.freeze(['secret', 'sca', 'sast', 'iac']);
export const FAST_ENGINES = Object.freeze(['secret', 'sast']);

/**
 * @param {object} args
 * @param {string} args.repoPath
 * @param {string[]} args.engines  subset of ALL_ENGINES
 * @param {object} [args.engineOpts]  per-engine options ({allowlistRegexes} → secrets)
 * @param {(msg:string)=>void} [args.onProgress]
 * @returns {Promise<{findings:Array, errors:Array<{engine:string,error:string}>}>}
 */
export async function runEngines({ repoPath, engines, engineOpts = {}, onProgress = () => {} }) {
  const valid = engines.filter((e) => ENGINE_RUNNERS[e]);
  const settled = await Promise.allSettled(
    valid.map(async (e) => {
      onProgress(`running ${e}…`);
      // engineOpts (secret allowlist) is passed to every engine; only scanSecrets
      // reads it — the others ignore the extra arg.
      const out = await ENGINE_RUNNERS[e](repoPath, engineOpts);
      onProgress(`${e}: ${out.length} finding(s)`);
      return out;
    })
  );

  const findings = [];
  const errors = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') findings.push(...r.value);
    else errors.push({ engine: valid[i], error: r.reason?.message || String(r.reason) });
  });
  return { findings, errors };
}
