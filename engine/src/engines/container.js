// Container engine — Dockerfile base-image vulnerability scanning via `trivy
// image` (Apache-2.0, binary already shipped for `trivy config`). Shift-left:
// catches vulnerable base images (node:20, python:3.11-slim, …) at commit time,
// distinct from cloud-security's runtime registry scan of deployed images.
//
// Flow: glob Dockerfiles → parse external FROM base images → `trivy image
// --scanners vuln` per UNIQUE image (Trivy pulls remotely, no docker daemon) →
// normalize to CONTAINER findings located at the Dockerfile FROM line.
//
// Cost guard: image pulls are the expensive part — MAX_IMAGES cap + per-image
// timeout. Private/unauthenticated images fail-soft (logged, skipped).

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdtemp, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { parseDockerfileFromImages, normalizeTrivyImageResults } from '../normalize.js';
import { findDockerfiles } from '../lib/dockerfiles.js';

const execFileAsync = promisify(execFile);

const TRIVY_BIN = process.env.APPSEC_TRIVY_BIN || 'trivy';
const IMAGE_TIMEOUT_MS = parseInt(process.env.APPSEC_CONTAINER_IMAGE_TIMEOUT_MS || `${5 * 60 * 1000}`, 10);
const MAX_IMAGES = parseInt(process.env.APPSEC_CONTAINER_MAX_IMAGES || '20', 10);
const MAX_DOCKERFILE_BYTES = 256 * 1024;

/**
 * Scan a repo's Dockerfile base images.
 * @returns {Promise<Array>} normalized AppSecFinding rows (type=CONTAINER)
 */
export async function scanContainer(repoPath) {
  const dockerfiles = await findDockerfiles(repoPath);
  if (!dockerfiles.length) return [];

  // Collect unique (image → first {dockerfile, line}) across all Dockerfiles.
  const imageLoc = new Map();
  for (const rel of dockerfiles) {
    const full = path.join(repoPath, rel);
    try {
      const st = await lstat(full);
      if (!st.isFile() || st.size > MAX_DOCKERFILE_BYTES) continue;
      const text = await readFile(full, 'utf8');
      for (const { image, line } of parseDockerfileFromImages(text)) {
        if (!imageLoc.has(image)) imageLoc.set(image, { dockerfile: rel, line });
      }
    } catch (err) {
      console.warn(`[APPSEC] container: skipped ${rel}: ${err.message}`);
    }
  }

  const images = [...imageLoc.keys()];
  if (images.length > MAX_IMAGES) {
    console.warn(`[APPSEC] container: ${images.length} base images found, capping at ${MAX_IMAGES}`);
  }

  const findings = [];
  for (const image of images.slice(0, MAX_IMAGES)) {
    const { dockerfile, line } = imageLoc.get(image);
    try {
      const report = await scanImage(image);
      findings.push(...normalizeTrivyImageResults(report, { image, dockerfile, line }));
    } catch (err) {
      // Private registries / pull failures / timeouts must not fail the whole
      // scan — log and move on (fault isolation, same posture as the SCA path).
      console.warn(`[APPSEC] container: trivy image ${image} failed: ${err.message}`);
    }
  }
  return findings;
}

/** Run `trivy image` for one ref and return the parsed JSON report. */
async function scanImage(image) {
  const reportDir = await mkdtemp(path.join(tmpdir(), 'appsec-trivy-img-'));
  const reportPath = path.join(reportDir, 'image.json');
  try {
    const args = [
      'image',
      '--scanners', 'vuln',         // vuln only — secrets/config covered by other engines
      '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
      '--format', 'json',
      '--output', reportPath,
      '--quiet',
      '--timeout', `${Math.floor(IMAGE_TIMEOUT_MS / 1000)}s`,
      image,
    ];
    try {
      await execFileAsync(TRIVY_BIN, args, { timeout: IMAGE_TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024 });
    } catch (err) {
      // Trivy exits 0 on found-vulns. A non-zero exit with a written report is
      // still usable; otherwise it's a real failure (pull error, bad ref).
      let wrote = false;
      try { await readFile(reportPath); wrote = true; } catch { /* not written */ }
      if (!wrote) throw new Error(`code=${err.code}: ${String(err.stderr || err.message).slice(0, 300)}`);
    }
    const raw = await readFile(reportPath, 'utf8');
    return raw.trim() ? JSON.parse(raw) : {};
  } finally {
    await rm(reportDir, { recursive: true, force: true }).catch(() => {});
  }
}
