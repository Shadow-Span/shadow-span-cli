// Locate Dockerfiles in a checked-out repo. Matches the common naming
// conventions (`Dockerfile`, `Dockerfile.prod`, `api.Dockerfile`) while pruning
// noise dirs (node_modules, .git, vendor) and bounding the walk depth so a
// pathological tree can't run away.

import { readdir } from 'node:fs/promises';
import path from 'node:path';

const PRUNE_DIRS = new Set(['.git', 'node_modules', 'vendor', '.next', 'dist', 'build', '.venv', '__pycache__']);
const MAX_DEPTH = 8;
const MAX_FILES = 200; // cap the result set — a repo with >200 Dockerfiles is pathological

/** True if a filename is a Dockerfile by convention. */
export function isDockerfileName(name) {
  return name === 'Dockerfile' || /(^|\.)dockerfile$/i.test(name) || /^Dockerfile\./.test(name);
}

/**
 * Recursively find Dockerfile paths (repo-relative) under `repoPath`.
 * @returns {Promise<string[]>}
 */
export async function findDockerfiles(repoPath) {
  const out = [];
  async function walk(dir, depth) {
    if (depth > MAX_DEPTH || out.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (out.length >= MAX_FILES) return;
      if (ent.isDirectory()) {
        if (PRUNE_DIRS.has(ent.name) || ent.name.startsWith('.')) continue;
        await walk(path.join(dir, ent.name), depth + 1);
      } else if (ent.isFile() && isDockerfileName(ent.name)) {
        out.push(path.relative(repoPath, path.join(dir, ent.name)));
      }
    }
  }
  await walk(repoPath, 0);
  return out;
}
