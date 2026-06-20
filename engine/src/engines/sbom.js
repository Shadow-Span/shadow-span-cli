// SBOM engine — full software bill of materials (with licenses) per repo
// checkout via `trivy fs --format cyclonedx` (Apache-2.0, binary already shipped
// for `trivy config`/`trivy image`).
//
// Why Trivy and not osv-scanner: Trivy's CycloneDX output carries package
// LICENSES (osv-scanner does not), which powers the SBOM viewer's copyleft /
// compliance filter. This is the FULL dependency inventory — vulnerable or not —
// distinct from the SCA engine (osv-scanner) which only emits vulnerable deps as
// AppSecFinding rows.
//
// Flow: `trivy fs --format cyclonedx --output <file> <repo>` → parse the
// CycloneDX `components[]` → normalized {purl, name, version, ecosystem,
// license} rows (see normalize.js#parseCycloneDxComponents). Fault-isolated:
// failure returns [] (logged) so it never breaks the finding-emitting engines.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { parseCycloneDxComponents } from '../normalize.js';

const execFileAsync = promisify(execFile);

const TRIVY_BIN = process.env.APPSEC_TRIVY_BIN || 'trivy';
const SBOM_TIMEOUT_MS = parseInt(process.env.APPSEC_SBOM_TIMEOUT_MS || `${5 * 60 * 1000}`, 10);
// Full license classification — Trivy's default SBOM only carries licenses a
// manifest declares inline (npm package-lock etc.); --license-full additionally
// scans license texts/declarations on disk (vendored deps, LICENSE files), widening
// coverage. Note: deps NOT present in the source clone (e.g. un-vendored Go modules
// resolved only from go.mod/go.sum) still can't be licensed — that needs the module
// cache, which a source-only ephemeral clone deliberately doesn't have. Env escape
// hatch in case the deeper scan regresses scan cost.
const LICENSE_FULL = process.env.APPSEC_SBOM_LICENSE_FULL !== 'false';

/**
 * Generate the SBOM for a checked-out repo directory.
 * @param {string} repoPath  local checkout
 * @returns {Promise<Array>} normalized package rows ({purl,name,version,ecosystem,license})
 */
export async function generateSbom(repoPath) {
  const reportDir = await mkdtemp(path.join(tmpdir(), 'appsec-trivy-sbom-'));
  const reportPath = path.join(reportDir, 'sbom.cdx.json');
  try {
    const args = [
      'fs',
      '--format', 'cyclonedx',
      '--output', reportPath,
      '--quiet',
      // HERMETIC: never reach out to a package registry. Without this, Trivy
      // resolves a lockfile-less pom.xml by fetching transitive POMs from Maven
      // Central — which (a) is a network call we don't want on an ephemeral clone
      // of customer source, and (b) gets rate-limited (observed HTTP 429 on GitLab
      // repos), and on a FATAL Trivy writes NO report, so the ENTIRE SBOM (npm,
      // pip, gem, go too) is lost, not just the Java part. Offline = direct deps
      // from the manifest, no remote tree-walk. The SCA engine (osv-scanner) still
      // covers vulnerable transitive deps independently.
      '--offline-scan',
      ...(LICENSE_FULL ? ['--license-full'] : []),
      '--timeout', `${Math.floor(SBOM_TIMEOUT_MS / 1000)}s`,
      repoPath,
    ];
    try {
      await execFileAsync(TRIVY_BIN, args, { timeout: SBOM_TIMEOUT_MS, maxBuffer: 128 * 1024 * 1024 });
    } catch (err) {
      // Trivy can exit non-zero while still writing a usable report; only treat
      // a missing report as a hard failure (same posture as iac.js/container.js).
      let wrote = false;
      try { await readFile(reportPath); wrote = true; } catch { /* not written */ }
      if (!wrote) throw new Error(`trivy fs sbom failed (code=${err.code}): ${String(err.stderr || err.message).slice(0, 300)}`);
    }
    const raw = await readFile(reportPath, 'utf8');
    const json = raw.trim() ? JSON.parse(raw) : {};
    return parseCycloneDxComponents(json);
  } finally {
    await rm(reportDir, { recursive: true, force: true }).catch(() => {});
  }
}
