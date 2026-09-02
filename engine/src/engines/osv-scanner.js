// SCA engine — osv-scanner (Apache-2.0, Google).
//
// Same OSV.dev dataset our intel pipeline already queries
// (apps/web/src/lib/intelligence/sources/vuln.js#fetchOsvRemediation), so SCA
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
import { scannerEnv } from '../lib/scanner-env.js';

import { normalizeOsvResults } from '../normalize.js';
import { enrichDependencyDepth } from '../lib/reachability.js';

const execFileAsync = promisify(execFile);

const OSV_TIMEOUT_MS = parseInt(process.env.APPSEC_OSV_TIMEOUT_MS || `${10 * 60 * 1000}`, 10);

// ── Offline OSV matching (#981 L1, flag-gated, DEFAULT OFF) ──────────────────
// When APPSEC_OSV_OFFLINE=true, osv-scanner matches against a LOCALLY-mirrored OSV
// database (populated daily into APPSEC_OSV_DB_DIR by the OSV→GCS mirror job)
// instead of calling the OSV.dev API per scan. This removes the per-scan external
// SPOF + rate-limit + latency. Default OFF = today's live-API behaviour — so the
// flag IS the runtime rollback.
//
// osv-scanner v2.3.8 (verified) has NO --local-db-path flag — it reads/writes its
// offline DB under os.UserCacheDir() = $XDG_CACHE_HOME/osv-scanner/. So we point
// XDG_CACHE_HOME at APPSEC_OSV_DB_DIR (the daily mirror job pre-populates
// $APPSEC_OSV_DB_DIR/osv-scanner/). `--offline-vulnerabilities` matches against the
// ALREADY-cached DB and does NOT hit the network; we deliberately do NOT pass
// --download-offline-databases in the scan path (scans are read-only against the
// shared snapshot). Args stay env-overridable for forward-compat across versions.
const OSV_OFFLINE = process.env.APPSEC_OSV_OFFLINE === 'true';
const OSV_OFFLINE_ARGS = (process.env.APPSEC_OSV_OFFLINE_ARGS || '--offline-vulnerabilities')
  .split(/\s+/)
  .filter(Boolean);
const OSV_DB_DIR = process.env.APPSEC_OSV_DB_DIR || '/var/osv-db';

/**
 * Child-process env for an osv-scanner run — points the offline DB cache at our
 * mirror, and drops OUR credentials (scannerEnv) so the scanner does not carry
 * the CLI's write token while parsing a repository we do not trust.
 */
function osvEnv() {
  return OSV_OFFLINE ? scannerEnv(process.env, { XDG_CACHE_HOME: OSV_DB_DIR }) : scannerEnv();
}

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
      // Go call analysis (govulncheck) is ON BY DEFAULT in osv-scanner v2 and is
      // disabled here for two independent reasons.
      //
      // 1. IT EXECUTES CODE FROM THE REPOSITORY BEING SCANNED. govulncheck loads
      //    and compiles packages, and osv-scanner's own help warns that call
      //    analysis "will run build scripts". We scan repositories we do not
      //    trust — a customer's, and in the dogfood case anything a contributor
      //    pushed — from CI runners that hold their credentials. A scanner must
      //    not be an execution vector for the thing it is scanning.
      //
      // 2. IT MAKES RESULTS DEPEND ON THE MACHINE. Call analysis silently drops
      //    "uncalled" advisories when the toolchain matches, and silently keeps
      //    them when govulncheck fails to load (a Go version mismatch, no Go at
      //    all). Verified 2026-09-02: identical trees, laptop reports the finding,
      //    a matching-Go runner would not. A gate whose verdict depends on which
      //    box ran it is not a gate.
      //
      // Reachability is still ours to decide — it is annotated separately
      // (sca-reachability.js) and recorded EXPLICITLY, with evidence, in
      // .shadowspan-suppressions.json. An unreachable advisory should be a
      // reviewed decision, not an invisible side-effect of the runner image.
      '--no-call-analysis=go',
    ];
    // osv-scanner respects .gitignore by default — correct for both fresh
    // clones (no ignored junk) and dev checkouts (skips node_modules). TRAP
    // (found dogfooding 2026-06-11): if the scan root itself sits inside a
    // directory an ENCLOSING repo gitignores (e.g. a worktree under
    // .claude/worktrees/), the walker silently skips everything and reports
    // zero sources. Set APPSEC_OSV_NO_IGNORE=true to disable ignore handling
    // in that situation.
    if (process.env.APPSEC_OSV_NO_IGNORE === 'true') args.push('--no-ignore');
    // Offline OSV matching (#981 L1) — flag-gated, default OFF (see top of file).
    if (OSV_OFFLINE) args.push(...OSV_OFFLINE_ARGS);
    args.push(repoPath);
    try {
      await execFileAsync('osv-scanner', args, {
        timeout: OSV_TIMEOUT_MS,
        maxBuffer: 16 * 1024 * 1024,
        env: osvEnv(),
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
    // DIRECT vs TRANSITIVE from the sibling manifest. Reachability itself is a whole-tree question
    // and is annotated later by the runner (services/appsec/src/sca-reachability.js), which is the
    // only place that can scope evidence to the right module. Best-effort — never throws.
    try {
      await enrichDependencyDepth(findings, repoPath);
    } catch (err) {
      console.warn(`[APPSEC] dependency-depth enrichment skipped: ${err.message}`);
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
      await execFileAsync('osv-scanner', args, { env: scannerEnv(), timeout: LICENSE_TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024 });
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
