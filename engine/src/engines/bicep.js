// Bicep engine — compile .bicep → ARM JSON (`bicep build`), then run the SAME
// Trivy config scan the IaC engine uses and remap every finding back to the
// .bicep source. Trivy evaluates ARM JSON natively but does NOT parse Bicep
// (Azure's IaC DSL), so a repo full of .bicep is invisible to `trivy config`.
// For the Azure customer, .bicep is the primary IaC format (#986).
//
// Why compile-then-scan (not a Bicep-native scanner): Trivy is already vendored
// for IaC + container scanning, its AZU-* misconfig policies operate on the
// compiled ARM, and the Bicep CLI is the canonical, supported compiler. No new
// rule pack to maintain.
//
// Line accuracy: the Bicep CLI's experimental source map is LSP-only (no stable
// build-CLI output), so we map findings by RESOURCE instead of raw lines. Each
// Trivy finding carries `Occurrences[].Resource = "resources[N]"` — the ARM
// resource index. We map ARM resources[N] → its type + per-type ordinal → the
// matching `resource <sym> '<type>@...'` declaration line in the .bicep. This is
// accurate per resource (the unit a customer acts on) and honest: evidence is
// tagged `compiledFromBicep` and the snippet/blame come from the .bicep source.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdtemp, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scannerEnv } from '../lib/scanner-env.js';

import { normalizeTrivyConfigResults } from '../normalize.js';
import { attachCodeContext } from '../code-context.js';
import { attachBlame } from '../git-blame.js';

const execFileAsync = promisify(execFile);

const BICEP_TIMEOUT_MS = parseInt(process.env.APPSEC_BICEP_TIMEOUT_MS || `${5 * 60 * 1000}`, 10);
const IAC_TIMEOUT_MS = parseInt(process.env.APPSEC_IAC_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

const BICEP_BIN = process.env.APPSEC_BICEP_BIN || 'bicep';
const TRIVY_BIN = process.env.APPSEC_TRIVY_BIN || 'trivy';

// Dirs we never descend into when hunting for .bicep files.
const SKIP_DIRS = new Set(['.git', 'node_modules', '.bicep', 'bin', 'obj', '.terraform', 'vendor']);
const MAX_BICEP_FILES = parseInt(process.env.APPSEC_BICEP_MAX_FILES || '500', 10);

/**
 * Recursively collect .bicep file paths under a repo, bounded + exclusion-aware.
 */
async function findBicepFiles(root) {
  const out = [];
  async function walk(dir) {
    if (out.length >= MAX_BICEP_FILES) return;
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= MAX_BICEP_FILES) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        await walk(full);
      } else if (e.isFile() && e.name.toLowerCase().endsWith('.bicep')) {
        out.push(full);
      }
    }
  }
  await walk(root);
  return out;
}

/**
 * Parse `resource <symbolic> '<type>@<api>' =` declarations from .bicep text.
 * @returns {Array<{ line:number, type:string, symbolic:string }>} in source order
 */
export function parseBicepResourceDecls(text) {
  const lines = String(text || '').split('\n');
  const decls = [];
  // resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  // resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  const re = /^\s*resource\s+([A-Za-z_]\w*)\s+'([^'@]+)(?:@[^']*)?'/;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (m) decls.push({ line: i + 1, type: m[2], symbolic: m[1] });
  }
  return decls;
}

/**
 * Build ARM-index → { type, ordinal } where ordinal is the 0-based position of
 * this resource among same-typed resources (ARM array order).
 */
export function indexArmResources(armJson) {
  const resources = Array.isArray(armJson?.resources) ? armJson.resources : [];
  const perType = new Map();
  return resources.map((r) => {
    const type = typeof r?.type === 'string' ? r.type : null;
    const ord = type ? (perType.get(type) || 0) : 0;
    if (type) perType.set(type, ord + 1);
    return { type, ordinal: ord };
  });
}

// Extract the ARM resource index N from a Trivy Occurrences[].Resource string
// like "resources[2].properties" → 2. Returns null if not a resources[N] ref.
export function armResourceIndex(occResource) {
  const m = /resources\[(\d+)\]/.exec(occResource || '');
  return m ? parseInt(m[1], 10) : null;
}

/**
 * Harvest ARM resource line-spans from every Occurrence across the report.
 * Trivy tags `{ Resource: "resources[N]", Location: { StartLine, EndLine } }`
 * (the resource's line range in the ARM JSON) on the findings that DO resolve
 * to a resource. We collect those once so "missing property" findings — which
 * only carry a document-level Occurrence but still have an ARM StartLine — can
 * be mapped by span-containment. @returns {Map<number,{start,end}>}
 */
export function harvestArmSpans(trivyJson) {
  const spans = new Map();
  for (const r of trivyJson?.Results || []) {
    for (const m of r?.Misconfigurations || []) {
      for (const o of m?.CauseMetadata?.Occurrences || []) {
        const n = armResourceIndex(o?.Resource);
        const loc = o?.Location;
        if (n !== null && Number.isInteger(loc?.StartLine) && Number.isInteger(loc?.EndLine) && !spans.has(n)) {
          spans.set(n, { start: loc.StartLine, end: loc.EndLine });
        }
      }
    }
  }
  return spans;
}

/**
 * Choose the best .bicep line for a Trivy misconfiguration, by resource.
 * Resolve the ARM resource index N two ways (most-specific first), then map
 * N → type + per-type ordinal → the kth .bicep declaration of that type:
 *   1. Occurrences with a `resources[N]` ref (present-but-wrong findings).
 *   2. Span-containment: the ARM StartLine falls inside resources[N]'s ARM line
 *      range (missing-property findings that only have a document Occurrence).
 * Falls back to first-of-type, then null (caller keeps file-level) so a finding
 * is never dropped.
 */
export function mapBicepLine(misconfig, armIndex, bicepDecls, armSpans) {
  const occ = Array.isArray(misconfig?.CauseMetadata?.Occurrences) ? misconfig.CauseMetadata.Occurrences : [];
  let n = null;
  for (const o of occ) {
    const idx = armResourceIndex(o?.Resource);
    if (idx !== null) { n = idx; break; }
  }
  if (n === null) {
    // Fallback: which ARM resource span contains this finding's ARM line?
    const armLine = misconfig?.CauseMetadata?.StartLine;
    if (Number.isInteger(armLine)) {
      let best = null;
      for (const [idx, { start, end }] of armSpans) {
        if (armLine >= start && armLine <= end) {
          // Prefer the tightest containing span (most specific resource).
          if (!best || (end - start) < (best.end - best.start)) best = { idx, start, end };
        }
      }
      if (best) n = best.idx;
    }
  }
  if (n === null || !armIndex[n]) return null;
  const { type, ordinal } = armIndex[n];
  if (!type) return null;
  const ofType = bicepDecls.filter((d) => d.type === type);
  if (ofType.length === 0) return null;
  return (ofType[ordinal] || ofType[0]).line;
}

/**
 * Compile + scan every .bicep under repoPath; return normalized IAC findings
 * keyed to the .bicep source (not the compiled ARM).
 * @returns {Promise<Array>} AppSecFinding-shaped rows (type=IAC)
 */
export async function scanBicep(repoPath) {
  const bicepFiles = await findBicepFiles(repoPath);
  if (bicepFiles.length === 0) return [];

  const workDir = await mkdtemp(path.join(tmpdir(), 'appsec-bicep-'));
  const all = [];
  try {
    for (let i = 0; i < bicepFiles.length; i++) {
      const bicepFile = bicepFiles[i];
      const armPath = path.join(workDir, `arm-${i}.json`);

      // 1. Compile .bicep → ARM JSON. A syntax error exits non-zero with no
      //    output — that's the customer's build problem, not a security
      //    finding; log + skip so one bad file can't sink the whole scan.
      // bicepFile is derived from walking a repository we do not trust. A path
      // beginning with `-` would be parsed as a FLAG by the bicep CLI, the same
      // class as the trivy image injection fixed in container.js. That one is
      // closed with a `--` separator; bicep is not, deliberately — bicep is not
      // installed here, so whether it honours `--` is unverified, and a guard we
      // can actually test beats a separator we cannot. Currently unreachable
      // (repoPath is absolutised before the walk), which is why the cheap check
      // is the right size of fix: it pins an invariant that lives in another file.
      if (path.basename(bicepFile).startsWith('-')) {
        console.warn(`[APPSEC] skipping bicep file with a leading dash: ${bicepFile}`);
        continue;
      }
      try {
        await execFileAsync(BICEP_BIN, ['build', bicepFile, '--outfile', armPath], {
          env: scannerEnv(), timeout: BICEP_TIMEOUT_MS,
          maxBuffer: 16 * 1024 * 1024,
        });
      } catch (err) {
        console.warn(`[bicep] compile failed for ${path.relative(repoPath, bicepFile)}: ${String(err.stderr || err.message).slice(0, 200)}`);
        continue;
      }

      // 2. Trivy-scan the compiled ARM JSON.
      let armJson;
      let trivyJson;
      try {
        armJson = JSON.parse(await readFile(armPath, 'utf8'));
      } catch { continue; }
      const reportPath = path.join(workDir, `report-${i}.json`);
      try {
        await execFileAsync(TRIVY_BIN, ['config', '--format', 'json', '--output', reportPath, '--quiet', armPath], {
          env: scannerEnv(), timeout: IAC_TIMEOUT_MS,
          maxBuffer: 32 * 1024 * 1024,
        });
      } catch (err) {
        let wrote = false;
        try { await readFile(reportPath); wrote = true; } catch { /* not written */ }
        if (!wrote) {
          console.warn(`[bicep] trivy failed for ${path.relative(repoPath, bicepFile)}: ${String(err.stderr || err.message).slice(0, 200)}`);
          continue;
        }
      }
      try {
        const raw = await readFile(reportPath, 'utf8');
        trivyJson = raw.trim() ? JSON.parse(raw) : {};
      } catch { continue; }

      // 3. Remap the raw Trivy JSON from the ARM JSON onto the .bicep source:
      //    rewrite Target → relative .bicep path, and each misconfig's
      //    StartLine/EndLine → the resource's declaration line in the .bicep.
      //    Then the shared normalize + code-context + blame pipeline operates
      //    on the .bicep transparently.
      const armIndex = indexArmResources(armJson);
      const armSpans = harvestArmSpans(trivyJson);
      const bicepDecls = parseBicepResourceDecls(await readFile(bicepFile, 'utf8'));
      const relBicep = path.relative(repoPath, bicepFile);
      for (const r of trivyJson?.Results || []) {
        r.Target = relBicep;
        for (const m of r?.Misconfigurations || []) {
          // Compute the mapped line from the ORIGINAL CauseMetadata before we
          // overwrite StartLine below (per-misconfig order preserves this).
          const mapped = mapBicepLine(m, armIndex, bicepDecls, armSpans);
          m.CauseMetadata = m.CauseMetadata || {};
          // mapped line, or file-level (1) when the resource can't be resolved.
          m.CauseMetadata.StartLine = mapped || 1;
          m.CauseMetadata.EndLine = mapped || 1; // resource-decl line; snippet ± window added by code-context
          // ARM JSON code excerpt is meaningless against .bicep — drop it so
          // attachCodeContext re-derives the snippet from the .bicep source.
          if (m.CauseMetadata.Code) delete m.CauseMetadata.Code;
        }
      }

      const findings = normalizeTrivyConfigResults(trivyJson, { repoRoot: repoPath });
      for (const f of findings) {
        f.evidence = { ...f.evidence, compiledFromBicep: true };
      }
      all.push(...findings);
    }

    // Code window + git blame against the .bicep sources.
    await attachCodeContext(all, repoPath);
    await attachBlame(all, repoPath);
    return all;
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

export function isBicepAvailable() {
  return execFileAsync(BICEP_BIN, ['--version'], { env: scannerEnv(), timeout: 10_000 }).then(() => true).catch(() => false);
}
