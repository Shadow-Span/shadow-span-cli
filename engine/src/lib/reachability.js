// DEPENDENCY DEPTH — is a vulnerable dependency one the project explicitly declares, or something
// pulled in five levels down? Read from the SIBLING manifest beside the lockfile osv-scanner
// reports. Ecosystems: npm, Go, PyPI. Result: `finding.dependencyDepth` ∈ DIRECT|TRANSITIVE|UNKNOWN.
//
// THIS FILE NO LONGER DECIDES REACHABILITY. It used to do both, and promoting the two answers into
// ONE column is what made the product unreadable: a row reading "Transitive" could not be
// distinguished from a row where reachability had simply not been computed, and a row reading
// "Reachable" silently outranked "Direct" — two different questions competing for one label.
//
// Reachability now lives in services/appsec/src/sca-reachability.js, which runs as a whole-tree
// pass in the runner (like the SAST pass) because the questions it must answer — which module root
// owns this file, is this test code, does this file import the exact path the advisory names — are
// tree-level and cannot be answered from inside a per-engine hook. See that file's header for the
// three defects the old import-grep produced on real data.
//
// Depth is genuinely manifest-local, so it stays here, beside the parsers that read the manifests.

import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

// PyPI normalizes names case-insensitively with -/_/. collapsed (PEP 503).
function normalizePyName(n) {
  return String(n || '').toLowerCase().replace(/[-_.]+/g, '-');
}

/** package.json → Set of declared dependency names (all dependency groups). */
export function parseNpmDirect(text) {
  const out = new Set();
  let json;
  try { json = JSON.parse(text); } catch { return out; }
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const name of Object.keys(json?.[key] || {})) out.add(name);
  }
  return out;
}

/** The `workspaces` globs a root package.json declares, normalized to an array. npm also accepts
 *  the object form `{ packages: [...] }` (the Yarn-compatible spelling).
 *  Ref: https://docs.npmjs.com/cli/v10/using-npm/workspaces */
export function parseNpmWorkspaceGlobs(text) {
  let json;
  try { json = JSON.parse(text); } catch { return []; }
  const w = json?.workspaces;
  const globs = Array.isArray(w) ? w : Array.isArray(w?.packages) ? w.packages : [];
  return globs.filter((g) => typeof g === 'string' && g && !g.startsWith('!'));
}

/** go.mod → Set of DIRECT module paths (require lines without `// indirect`). */
export function parseGoModDirect(text) {
  const out = new Set();
  const lines = String(text || '').split('\n');
  let inBlock = false;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('require (')) { inBlock = true; continue; }
    if (inBlock && line === ')') { inBlock = false; continue; }
    if (line.includes('// indirect')) continue; // transitive
    const m = inBlock
      ? line.match(/^([^\s]+)\s+v\S+/)
      : line.match(/^require\s+([^\s]+)\s+v\S+/);
    if (m) out.add(m[1]);
  }
  return out;
}

/** requirements.txt / pyproject.toml / Pipfile → Set of normalized dist names. */
export function parsePyDirect(text, filename = '') {
  const out = new Set();
  const base = path.basename(filename).toLowerCase();
  const src = String(text || '');
  if (base.startsWith('requirements') || base === 'constraints.txt') {
    for (const raw of src.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;
      const m = line.match(/^([A-Za-z0-9._-]+)/);
      if (m) out.add(normalizePyName(m[1]));
    }
    return out;
  }
  if (base === 'pyproject.toml' || base === 'pipfile') {
    // Line-based name extraction (no TOML dep): catch `name = "..."`, list-style
    // `"name>=x"`, and poetry `name = {version=…}`. Good enough for membership.
    for (const raw of src.split('\n')) {
      const line = raw.trim();
      const dep = line.match(/^["']?([A-Za-z0-9._-]+)["']?\s*[=:]/) || line.match(/^["']([A-Za-z0-9._-]+)[><=~!]/);
      if (dep) out.add(normalizePyName(dep[1]));
    }
    return out;
  }
  return out;
}

// Ecosystem → manifest filenames to look for beside the lockfile.
const MANIFESTS = {
  npm: ['package.json'],
  Go: ['go.mod'],
  PyPI: ['requirements.txt', 'pyproject.toml', 'Pipfile'],
};

function matchName(ecosystem, pkgName, directSet) {
  if (ecosystem === 'PyPI') return directSet.has(normalizePyName(pkgName));
  return directSet.has(pkgName);
}

/**
 * Enrich SCA findings in place with `dependencyDepth` ∈ DIRECT|TRANSITIVE|UNKNOWN.
 *
 * UNKNOWN is load-bearing and means "no manifest we could parse sat beside this lockfile" — it
 * must not be read as TRANSITIVE. The distinction decides a real verdict downstream: a DIRECT
 * dependency nothing imports is an unused dependency, whereas the same absence on a TRANSITIVE one
 * says nothing at all (see sca-reachability.js#classify).
 *
 * @param {Array} findings  normalized findings (only type=SCA are touched)
 * @param {string} repoPath repo checkout root
 */
export async function enrichDependencyDepth(findings, repoPath) {
  // Cache parsed direct-dep sets per (dir, ecosystem) so we read each manifest once.
  const cache = new Map();

  async function directSetFor(ecosystem, lockfileRel) {
    const dir = lockfileRel ? path.dirname(lockfileRel) : '.';
    const cacheKey = `${ecosystem}::${dir}`;
    if (cache.has(cacheKey)) return cache.get(cacheKey);
    const candidates = MANIFESTS[ecosystem];
    let set = null; // null = no parseable manifest → UNKNOWN
    if (candidates) {
      for (const fname of candidates) {
        try {
          const text = await readFile(path.join(repoPath, dir, fname), 'utf8');
          const parsed =
            ecosystem === 'npm' ? parseNpmDirect(text)
            : ecosystem === 'Go' ? parseGoModDirect(text)
            : parsePyDirect(text, fname);
          if (parsed.size) { set = set || new Set(); for (const n of parsed) set.add(n); }
          // NPM WORKSPACES: one lockfile at the root, but the dependencies are declared in the
          // MEMBER manifests. Reading only the root package.json made every workspace dependency
          // look transitive — on this monorepo the root declares exactly one dependency, so all 93
          // npm findings were reported TRANSITIVE including @anthropic-ai/sdk, which
          // packages/ai/package.json declares outright. Depth then silently mislabels every
          // monorepo, and the "unused direct dependency" verdict downstream can never fire.
          if (ecosystem === 'npm') {
            for (const wsText of await readWorkspaceManifests(repoPath, dir, parseNpmWorkspaceGlobs(text))) {
              const wsDeps = parseNpmDirect(wsText);
              if (wsDeps.size) { set = set || new Set(); for (const n of wsDeps) set.add(n); }
            }
          }
        } catch { /* manifest not present here */ }
      }
    }
    cache.set(cacheKey, set);
    return set;
  }

  for (const f of findings) {
    if (f.type !== 'SCA') continue;
    const ecosystem = f.packageEcosystem;
    const lockfile = f.evidence?.lockfile || f.file || null;
    const directSet = await directSetFor(ecosystem, lockfile);
    let depth = 'UNKNOWN';
    if (directSet) depth = matchName(ecosystem, f.packageName, directSet) ? 'DIRECT' : 'TRANSITIVE';
    f.dependencyDepth = depth; // top-level column — filter + sort, and an input to reachability
  }
  return findings;
}

/** Bound on workspace-manifest reads, so a pathological `workspaces` glob cannot stall a scan. */
const MAX_WORKSPACE_MANIFESTS = 400;

/**
 * Read the package.json of every workspace member matched by `globs`.
 *
 * Deliberately handles only the two forms npm workspaces actually use in the wild — a literal
 * directory (`packages/db`) and a single trailing star (`packages/*`) — because anything richer
 * would need a glob engine, and a wrong expansion here silently changes a dependency's DEPTH
 * rather than failing. Unmatched patterns simply contribute nothing.
 */
async function readWorkspaceManifests(repoPath, dir, globs) {
  const texts = [];
  for (const glob of globs) {
    if (texts.length >= MAX_WORKSPACE_MANIFESTS) break;
    const star = glob.indexOf('*');
    let members = [];
    if (star === -1) {
      members = [glob];
    } else if (glob.endsWith('/*') || glob.endsWith('/**')) {
      const parent = glob.replace(/\/\*+$/, '');
      try {
        const entries = await readdir(path.join(repoPath, dir, parent), { withFileTypes: true });
        members = entries.filter((e) => e.isDirectory()).map((e) => path.posix.join(parent, e.name));
      } catch { members = []; }
    }
    for (const m of members) {
      if (texts.length >= MAX_WORKSPACE_MANIFESTS) break;
      try { texts.push(await readFile(path.join(repoPath, dir, m, 'package.json'), 'utf8')); }
      catch { /* not a workspace member after all */ }
    }
  }
  return texts;
}
