// SCA reachability — rank each vulnerable dependency by how likely it is to
// actually matter, the noise-reduction Aikido/Cycode/Snyk lead with. Two tiers:
//
//   1. DIRECT vs TRANSITIVE (reachability-LITE) — is the dep one the project
//      explicitly declares, or pulled in five levels down? Read the SIBLING
//      manifest beside the lockfile osv-scanner reports. Ecosystems: npm, Go, PyPI.
//   2. IMPORTED (reachability-V1) — is the vulnerable package actually IMPORTED in
//      source? A single bounded walk of the source tree greps import statements;
//      a package whose import-symbol appears is REACHABLE (highest priority). Only
//      ecosystems where the package name maps cleanly to the import symbol are
//      covered: npm (name = specifier root), Go (module path = import path),
//      RubyGems (separator-normalized). Python/Java/etc. have no clean name→import
//      mapping, so they STAY at DIRECT/TRANSITIVE — honest, never a false REACHABLE.
//
// Resulting `evidence.reachability = { dependency, imported, tier }` and the
// promoted top-level `finding.reachability = tier` (REACHABLE|DIRECT|TRANSITIVE|
// UNKNOWN) which the UI filters + sorts on. True call-graph reachability (proving
// the vulnerable FUNCTION is invoked) is osv-scanner --call-analysis, left
// env-gated-off because it runs build scripts on untrusted customer source.

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

// ── Import-symbol reachability (V1) ──────────────────────────────────────────

// Bounds so a pathological repo can't hang or OOM the walk. On exceed we return
// whatever was collected — import detection degrades to "not detected" (tier
// falls back to DIRECT/TRANSITIVE), never a wrong REACHABLE.
const WALK_MAX_FILES = parseInt(process.env.APPSEC_REACH_MAX_FILES || '12000', 10);
const WALK_MAX_FILE_BYTES = 512 * 1024;
const WALK_DEADLINE_MS = parseInt(process.env.APPSEC_REACH_DEADLINE_MS || '20000', 10);
const EXCLUDE_DIRS = new Set([
  'node_modules', 'vendor', '.git', 'dist', 'build', 'out', '.next', '.nuxt',
  'target', '__pycache__', '.venv', 'venv', '.tox', '.gradle', 'bin', 'obj',
  'coverage', '.terraform', 'testdata', 'fixtures', '.cache',
]);

// Source extension → ecosystem whose imports it carries.
const EXT_ECOSYSTEM = {
  '.js': 'npm', '.jsx': 'npm', '.ts': 'npm', '.tsx': 'npm', '.mjs': 'npm', '.cjs': 'npm',
  '.go': 'Go',
  '.rb': 'RubyGems',
};

function normSep(s) { return String(s || '').toLowerCase().replace(/[-_]/g, ''); }

// JS/TS: import/require/dynamic-import specifiers → the package ROOT (handles
// scoped @org/pkg and subpath pkg/sub). Skips relative + node: builtins.
function extractJsImports(text, set) {
  const re = /(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(text))) {
    const spec = m[1];
    if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) continue;
    const parts = spec.split('/');
    const root = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
    if (root) set.add(root);
  }
}

// Go: quoted import paths (single + block form). Full path; matched by prefix
// against the module path later (a finding's module may be imported via a subpkg).
function extractGoImports(text, set) {
  const re = /\bimport\s+(?:\(\s*([\s\S]*?)\)|((?:_\s+|\.\s+)?"[^"]+"))/g;
  let m;
  while ((m = re.exec(text))) {
    const body = m[1] || m[2] || '';
    const q = body.match(/"([^"]+)"/g) || [];
    for (const s of q) { const p = s.slice(1, -1); if (p) set.add(p); }
  }
}

// Ruby: require 'gem' (skip require_relative). Root before first '/'; matched
// separator-normalized (gem rest-client → require 'rest_client').
function extractRubyImports(text, set) {
  const re = /\brequire\s+['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(text))) {
    const spec = m[1];
    if (!spec || spec.startsWith('.')) continue;
    set.add(normSep(spec.split('/')[0]));
  }
}

const EXTRACTORS = { npm: extractJsImports, Go: extractGoImports, RubyGems: extractRubyImports };

/**
 * ONE bounded walk of the source tree, collecting imported symbols per ecosystem.
 * @returns {Promise<{npm:Set,Go:Set,RubyGems:Set}>}
 */
export async function collectImports(repoPath) {
  const sets = { npm: new Set(), Go: new Set(), RubyGems: new Set() };
  const deadline = Date.now() + WALK_DEADLINE_MS;
  let filesRead = 0;
  const stack = ['.'];
  while (stack.length) {
    if (Date.now() > deadline || filesRead >= WALK_MAX_FILES) break;
    const rel = stack.pop();
    let entries;
    try { entries = await readdir(path.join(repoPath, rel), { withFileTypes: true }); }
    catch { continue; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue; // don't follow symlinks out of the tree
      if (e.isDirectory()) {
        if (!EXCLUDE_DIRS.has(e.name) && !e.name.startsWith('.')) stack.push(path.join(rel, e.name));
        continue;
      }
      const eco = EXT_ECOSYSTEM[path.extname(e.name).toLowerCase()];
      if (!eco) continue;
      if (filesRead >= WALK_MAX_FILES || Date.now() > deadline) break;
      try {
        const text = await readFile(path.join(repoPath, rel, e.name), 'utf8');
        filesRead++;
        EXTRACTORS[eco](text.length > WALK_MAX_FILE_BYTES ? text.slice(0, WALK_MAX_FILE_BYTES) : text, sets[eco]);
      } catch { /* unreadable/binary — skip */ }
    }
  }
  return sets;
}

// Is the vulnerable package's import-symbol present? Returns:
//   true  — imported (REACHABLE)
//   false — checked + not found (a clean-mapping ecosystem with import data)
//   null  — undetermined (ecosystem unsupported, or no source of that type found)
// null never produces a false REACHABLE *or* a false "not imported".
function isImported(ecosystem, pkgName, importSets) {
  if (!pkgName) return null;
  if (ecosystem === 'npm') return importSets.npm.size ? importSets.npm.has(pkgName) : null;
  if (ecosystem === 'RubyGems') return importSets.RubyGems.size ? importSets.RubyGems.has(normSep(pkgName)) : null;
  if (ecosystem === 'Go') {
    if (!importSets.Go.size) return null;
    if (importSets.Go.has(pkgName)) return true;
    for (const p of importSets.Go) if (p.startsWith(pkgName + '/')) return true;
    return false;
  }
  return null; // PyPI / Maven / NuGet / Composer — no clean name→import mapping in v1
}

/**
 * Enrich SCA findings in place with evidence.reachability:
 *   { dependency: 'DIRECT'|'TRANSITIVE'|'UNKNOWN' }
 * @param {Array} findings  normalized findings (only type=SCA are touched)
 * @param {string} repoPath repo checkout root
 */
export async function enrichReachability(findings, repoPath) {
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
        } catch { /* manifest not present here */ }
      }
    }
    cache.set(cacheKey, set);
    return set;
  }

  // ONE source-tree walk for import symbols — only when there's an SCA finding in
  // a clean-mapping ecosystem (npm/Go/RubyGems). Skip the walk entirely otherwise.
  const scaEcos = new Set(findings.filter((f) => f.type === 'SCA').map((f) => f.packageEcosystem));
  const needWalk = ['npm', 'Go', 'RubyGems'].some((e) => scaEcos.has(e));
  let importSets = { npm: new Set(), Go: new Set(), RubyGems: new Set() };
  if (needWalk) {
    try { importSets = await collectImports(repoPath); }
    catch { /* leave empty → imported stays null, tier falls back to dependency */ }
  }

  for (const f of findings) {
    if (f.type !== 'SCA') continue;
    const ecosystem = f.packageEcosystem;
    const lockfile = f.evidence?.lockfile || f.file || null;
    const directSet = await directSetFor(ecosystem, lockfile);
    let dependency = 'UNKNOWN';
    if (directSet) dependency = matchName(ecosystem, f.packageName, directSet) ? 'DIRECT' : 'TRANSITIVE';
    const imported = needWalk ? isImported(ecosystem, f.packageName, importSets) : null;
    // REACHABLE only on a positive import hit; otherwise the DIRECT/TRANSITIVE tier.
    const tier = imported === true ? 'REACHABLE' : dependency;
    f.evidence = { ...(f.evidence || {}), reachability: { dependency, imported, tier } };
    f.reachability = tier; // promoted to a top-level column for filter + sort
  }
  return findings;
}
