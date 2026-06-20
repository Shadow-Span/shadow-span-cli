// SCA engine — osv-scanner (Apache-2.0, Google).
//
// Same OSV.dev dataset our intel pipeline already queries
// (the Shadow Span platform), so SCA
// findings join existing Vulnerability rows via CVE alias with zero new feed
// plumbing.
//
// CLI (v2.x, pinned in Dockerfile): osv-scanner scan source -r --format json
// Exit codes: 0 = clean, 1 = vulnerabilities found (still a successful scan),
// anything else = real failure.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { normalizeOsvResults } from '../normalize.js';
import { enrichReachability } from '../lib/reachability.js';

const execFileAsync = promisify(execFile);

const OSV_TIMEOUT_MS = parseInt(process.env.APPSEC_OSV_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

/**
 * Run osv-scanner against a checked-out repo directory.
 * @returns {Promise<Array>} normalized AppSecFinding-shaped rows (type=SCA)
 */
export async function scanSca(repoPath) {
  const workDir = await mkdtemp(path.join(tmpdir(), 'appsec-osv-'));
  const reportPath = path.join(workDir, 'osv-report.json');
  try {
    const args = [
      'scan', 'source',
      '--recursive',
      '--format', 'json',
      '--output-file', reportPath,
      // A repo with zero lockfiles is a valid empty result, not an error.
      '--allow-no-lockfiles',
    ];
    // osv-scanner respects .gitignore by default — correct for both fresh
    // clones (no ignored junk) and dev checkouts (skips node_modules). TRAP
    // (found dogfooding 2026-06-11): if the scan root itself sits inside a
    // directory an ENCLOSING repo gitignores (e.g. a worktree under
    // .claude/worktrees/), the walker silently skips everything and reports
    // zero sources. Set APPSEC_OSV_NO_IGNORE=true to disable ignore handling
    // in that situation.
    if (process.env.APPSEC_OSV_NO_IGNORE === 'true') args.push('--no-ignore');
    args.push(repoPath);
    try {
      await execFileAsync('osv-scanner', args, {
        timeout: OSV_TIMEOUT_MS,
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (err) {
      // exit 1 = "vulnerabilities were found" — the report file is valid.
      if (err.code !== 1) {
        throw new Error(`osv-scanner failed (code=${err.code}): ${truncate(err.stderr || err.message)}`);
      }
    }

    const raw = await readFile(reportPath, 'utf8');
    const json = JSON.parse(raw);
    const findings = normalizeOsvResults(json, { repoRoot: repoPath });
    // Reachability-lite: classify each vuln dep as DIRECT vs TRANSITIVE from the
    // sibling manifest (noise-reduction prioritization). Best-effort — never throws.
    try {
      await enrichReachability(findings, repoPath);
    } catch (err) {
      console.warn(`[APPSEC] reachability enrichment skipped: ${err.message}`);
    }
    return findings;
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

const LICENSE_TIMEOUT_MS = parseInt(process.env.APPSEC_OSV_LICENSE_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

/**
 * Capture per-dependency licenses via osv-scanner's `--licenses` mode. osv.dev
 * (the vuln database) carries NO license data — this is the COMPANION deps.dev
 * metadata, surfaced by the SAME binary we already run for SCA. Used to backfill
 * SBOM packages that trivy left license-less and to feed the license-policy gate
 * real licenses (not just "unknown"). Network = deps.dev metadata lookups keyed
 * by the already-public package name+version — NOT a source/registry tree-walk,
 * so it doesn't reintroduce the hermetic concern that made the trivy SBOM offline.
 *
 * @returns {Promise<Map<string,string>>} "name@version" (lowercased) → license string
 */
export async function collectDependencyLicenses(repoPath) {
  const workDir = await mkdtemp(path.join(tmpdir(), 'appsec-osvlic-'));
  const reportPath = path.join(workDir, 'osv-licenses.json');
  const map = new Map();
  try {
    const args = [
      'scan', 'source', '--recursive', '--allow-no-lockfiles',
      // Any allowlist value triggers license COLLECTION; we read the raw
      // `licenses[]` field per package ourselves and ignore osv-scanner's
      // pass/fail verdict (our own license-policy engine decides). MUST be the
      // `--licenses=<x>` equals-form — the space form is parsed as a positional
      // path ("stat …/Apache-2.0: no such file") and the whole run fails.
      '--licenses=Apache-2.0',
      // --no-ignore so the license pass walks the SAME files trivy's SBOM does.
      // Without it osv-scanner honors .gitignore and can skip lockfiles trivy
      // still lists → those packages stay license-less ("unknown") forever. The
      // license pass is metadata-only, so scanning ignored manifests is safe.
      '--no-ignore',
      // --output-file, not the deprecated --output (v2.3.8 warns + the run errors).
      '--format', 'json', '--output-file', reportPath,
    ];
    args.push(repoPath);
    try {
      await execFileAsync('osv-scanner', args, { timeout: LICENSE_TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024 });
    } catch (err) {
      // exit 1 = a license "violation" against the dummy allowlist — the report
      // is still written; only a missing report is a real failure.
      let wrote = false;
      try { await readFile(reportPath); wrote = true; } catch { /* not written */ }
      if (!wrote) throw new Error(`osv-scanner --licenses failed (code=${err.code}): ${truncate(err.stderr || err.message)}`);
    }
    const json = JSON.parse(await readFile(reportPath, 'utf8'));
    for (const r of (json.results || [])) {
      for (const p of (r.packages || [])) {
        const lic = (p.licenses || []).filter((l) => l && l !== 'UNKNOWN');
        const name = p.package?.name;
        const ver = p.package?.version;
        if (!lic.length || !name || !ver) continue;
        // Multiple → dual-license choice; OR is what our classifier expects.
        map.set(`${name}@${ver}`.toLowerCase(), lic.join(' OR '));
      }
    }
    return map;
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

function truncate(s, max = 500) {
  return String(s || '').slice(0, max);
}
