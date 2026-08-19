// AppSecFinding upsert + diff — the idempotent write path.
//
// Mirrors the posture-runner contract: identityKey is the stable upsert key
// (@@unique([orgId, repositoryId, identityKey])), and the diff against the
// previous scan determines which rows are NEW (alertable), RE-OBSERVED
// (silent lastSeenAt bump) or CLOSED (re-scan no longer sees them →
// REMEDIATED + fixedAt). Analyst-driven states (FALSE_POSITIVE /
// ACCEPTED_RISK) are never touched by the scanner.

const CHUNK = 200;

function chunk(arr, size = CHUNK) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/**
 * Idempotent upsert + diff, scoped to EITHER a repo (repositoryId) OR a DAST
 * target (targetId). Exactly one scope is passed; the other stays null on the
 * row, and the matching scope-specific @@unique constraint dedups.
 *
 * @param {object} prisma  @shadow-span/db client
 * @param {object} args
 * @param {string} args.orgId
 * @param {string} [args.repositoryId]  repo scope (SAST/SCA/IAC/SECRET)
 * @param {string} [args.targetId]      DAST scope (AppSecDastTarget.id)
 * @param {string} [args.assetId]       optional Asset link for DAST findings
 * @param {string} args.scanId
 * @param {Array}  args.findings  normalized rows from src/normalize.js
 * @returns {Promise<{created:number, reobserved:number, closed:number, newFindings:Array}>}
 */
export async function upsertAppSecFindings(prisma, { orgId, repositoryId, targetId, assetId, scanId, findings, closeStale = true }) {
  const scopeWhere = repositoryId ? { repositoryId } : { targetId };

  // Dedup incoming by identityKey (e.g. the same OSV id from two lockfiles —
  // identityKey excludes the lockfile path for SCA, so collisions are expected).
  const byKey = new Map();
  for (const f of findings) {
    if (!byKey.has(f.identityKey)) byKey.set(f.identityKey, f);
  }
  const incoming = [...byKey.values()];

  const existing = await prisma.appSecFinding.findMany({
    where: { orgId, ...scopeWhere },
    select: { id: true, identityKey: true, status: true },
  });
  const existingByKey = new Map(existing.map((e) => [e.identityKey, e]));

  const now = new Date();
  const toCreate = [];
  const reobservedKeys = [];
  for (const f of incoming) {
    const prior = existingByKey.get(f.identityKey);
    if (!prior) {
      toCreate.push({
        orgId,
        repositoryId: repositoryId ?? null,
        targetId: targetId ?? null,
        targetUrl: f.targetUrl ?? null,
        assetId: assetId ?? null,
        scanId,
        type: f.type,
        ruleId: f.ruleId,
        ruleName: f.ruleName,
        severity: f.severity,
        file: f.file,
        line: f.line,
        column: f.column,
        description: f.description,
        remediation: f.remediation,
        cveId: f.cveId,
        packageName: f.packageName,
        packageEcosystem: f.packageEcosystem,
        packageVersion: f.packageVersion,
        fixedVersion: f.fixedVersion,
        cwe: f.cwe,
        reachability: f.reachability ?? null,
        dependencyDepth: f.dependencyDepth ?? null,
        identityKey: f.identityKey,
        evidence: f.evidence ?? undefined,
        firstSeenAt: now,
        lastSeenAt: now,
      });
    } else {
      reobservedKeys.push(f.identityKey);
    }
  }

  // CLOSE: previously OPEN rows the re-scan did not re-observe. Only
  // scanner-owned statuses flip — analyst decisions are sticky.
  //
  // closeStale=false for PARTIAL scans (a CLI --diff / --staged run, or any
  // engine-subset run): the scan only saw a subset of the repo, so absence of
  // a finding is NOT evidence it's fixed. Partial scans only add/reopen; a FULL
  // scan (server runner, or CLI full `scan`) is authoritative for closure.
  const incomingKeys = new Set(incoming.map((f) => f.identityKey));
  const closedKeys = closeStale
    ? existing
        .filter((e) => (e.status === 'OPEN' || e.status === 'IN_PROGRESS') && !incomingKeys.has(e.identityKey))
        .map((e) => e.identityKey)
    : [];

  for (const keys of chunk(toCreate)) {
    await prisma.appSecFinding.createMany({ data: keys, skipDuplicates: true });
  }
  let reobserved = 0;
  // Per-row update (not updateMany) so each re-observed finding gets its CURRENT
  // scanner-owned payload — evidence (code-context window + suggested fix),
  // severity, message, remediation. Without this, a finding created by an older
  // scanner build keeps stale evidence forever (e.g. no codeContext/fix), and an
  // improved rule message never reaches existing rows. identityKey pins
  // type:ruleId:file:line, so file/line are stable across a re-observe; analyst
  // fields (status, dismissedReason) are untouched here.
  const incomingByKey = new Map(incoming.map((f) => [f.identityKey, f]));
  const reobservedRows = reobservedKeys
    .map((k) => ({ id: existingByKey.get(k)?.id, f: incomingByKey.get(k) }))
    .filter((r) => r.id && r.f);
  // Smaller batches than CHUNK: each row is its own UPDATE, so cap concurrent
  // connections taken from the pg pool.
  for (const batch of chunk(reobservedRows, 25)) {
    await Promise.all(
      batch.map(({ id, f }) =>
        prisma.appSecFinding.update({
          where: { orgId_id: { orgId, id } },
          data: {
            lastSeenAt: now,
            scanId,
            fixedAt: null,
            severity: f.severity,
            ruleName: f.ruleName,
            description: f.description,
            remediation: f.remediation,
            cwe: f.cwe,
            column: f.column,
            reachability: f.reachability ?? null,
            // Depth is manifest-derived and CHANGES when a dependency is promoted from transitive to
            // declared (or dropped to indirect). Freezing it at create time would keep reporting an
            // "unused direct dependency" that is no longer direct.
            dependencyDepth: f.dependencyDepth ?? null,
            evidence: f.evidence ?? undefined,
            // packageVersion (installed) + fixedVersion are scanner-owned AND mutable AND NOT pinned by
            // identityKey (SCA/SBOM/CONTAINER identity = type:ruleId:ecosystem:package, version-free — see
            // buildIdentityKey). They CAN legitimately drift on a re-observe: a dependency bump changes the
            // installed version; an advisory update or a fix to the extractor changes the fixed version.
            // Omitting them froze the row at CREATE-time values — e.g. a corrected fixedVersion (7.29.6)
            // showed in `remediation` text but the `fixedVersion` COLUMN kept the stale 8.0.0-rc.6, and the
            // AVR resolver (planSafeUpgrade reads BOTH columns) still mis-routed to a backport. Refresh them.
            packageVersion: f.packageVersion,
            fixedVersion: f.fixedVersion,
          },
        })
      )
    );
    reobserved += batch.length;
  }
  // A re-observed finding that was previously auto-closed must re-open —
  // but never resurrect FALSE_POSITIVE / ACCEPTED_RISK.
  //
  // CLOSED is included alongside REMEDIATED: closeFindingsForInactiveRepos uses CLOSED when a
  // repository stops being tracked, and re-observing it means the repository is BACK (token
  // restored, repo re-added). Without this the deactivation would be a one-way door — the finding
  // would sit CLOSED forever while the scanner kept seeing it every run.
  for (const keys of chunk(reobservedKeys)) {
    await prisma.appSecFinding.updateMany({
      where: { orgId, ...scopeWhere, identityKey: { in: keys }, status: { in: ['REMEDIATED', 'CLOSED'] } },
      data: { status: 'OPEN', fixedAt: null },
    });
  }
  let closed = 0;
  for (const keys of chunk(closedKeys)) {
    const r = await prisma.appSecFinding.updateMany({
      where: { orgId, ...scopeWhere, identityKey: { in: keys }, status: { in: ['OPEN', 'IN_PROGRESS'] } },
      data: { status: 'REMEDIATED', fixedAt: now },
    });
    closed += r.count;
  }

  return {
    created: toCreate.length,
    reobserved,
    closed,
    newFindings: toCreate,
  };
}

/**
 * Idempotent SBOM upsert — dedup on (orgId, repositoryId, purl). New packages
 * are created; re-observed packages get lastSeenAt + license/version refreshed;
 * stale packages (a re-scan no longer lists them) are DELETED (the SBOM is a
 * point-in-time inventory, not a workflow surface — no analyst state to keep).
 *
 * @param {object} prisma  @shadow-span/db client
 * @param {object} args
 * @param {string} args.orgId
 * @param {string} args.repositoryId
 * @param {Array}  args.packages  rows from normalize.js#parseCycloneDxComponents
 * @param {boolean} [args.pruneStale=true]  delete packages not in this scan
 * @returns {Promise<{created:number, reobserved:number, removed:number, total:number}>}
 */
export async function upsertRepoPackages(prisma, { orgId, repositoryId, packages, pruneStale = true }) {
  // Dedup incoming by purl (a package can appear in two lockfiles).
  const byPurl = new Map();
  for (const p of packages) {
    if (p?.purl && !byPurl.has(p.purl)) byPurl.set(p.purl, p);
  }
  const incoming = [...byPurl.values()];

  const existing = await prisma.appSecRepoPackage.findMany({
    where: { orgId, repositoryId },
    select: { id: true, purl: true },
  });
  const existingByPurl = new Map(existing.map((e) => [e.purl, e]));

  const now = new Date();
  const toCreate = [];
  const reobservedRows = [];
  for (const p of incoming) {
    const prior = existingByPurl.get(p.purl);
    if (!prior) {
      toCreate.push({
        orgId,
        repositoryId,
        purl: p.purl,
        name: p.name,
        version: p.version ?? null,
        ecosystem: p.ecosystem ?? null,
        license: p.license ?? null,
        firstSeenAt: now,
        lastSeenAt: now,
      });
    } else {
      reobservedRows.push({ id: prior.id, p });
    }
  }

  const incomingPurls = new Set(incoming.map((p) => p.purl));
  const staleIds = pruneStale
    ? existing.filter((e) => !incomingPurls.has(e.purl)).map((e) => e.id)
    : [];

  for (const keys of chunk(toCreate)) {
    await prisma.appSecRepoPackage.createMany({ data: keys, skipDuplicates: true });
  }
  let reobserved = 0;
  for (const batch of chunk(reobservedRows, 25)) {
    await Promise.all(
      batch.map(({ id, p }) =>
        prisma.appSecRepoPackage.update({
          where: { orgId_id: { orgId, id } },
          // STICKY license: only overwrite when THIS scan resolved one. The
          // deps.dev license backfill (osv-scanner --licenses) returns slightly
          // different package subsets per run; without this guard a run that
          // missed a gem would null out a license a prior run already resolved.
          data: {
            lastSeenAt: now,
            version: p.version ?? null,
            ecosystem: p.ecosystem ?? null,
            ...(p.license ? { license: p.license } : {}),
          },
        })
      )
    );
    reobserved += batch.length;
  }
  let removed = 0;
  for (const ids of chunk(staleIds)) {
    const r = await prisma.appSecRepoPackage.deleteMany({ where: { orgId, repositoryId, id: { in: ids } } });
    removed += r.count;
  }

  return { created: toCreate.length, reobserved, removed, total: incoming.length };
}

/**
 * Close the findings of repositories that are no longer tracked.
 *
 * THE RULE: if the SOURCE is not active, its findings are not active. A repository the SCM token can
 * no longer see is gone — deleted, transferred, or access revoked — and an OPEN finding on it is not
 * something anyone can act on. Leaving them open inflates the open count, skews any time-to-remediate
 * metric, and grows without bound as repositories churn.
 *
 * FOUND 2026-08-08. Discovery already marked such repositories `isActive=false` ("kept for history"),
 * and nothing downstream honoured it: /api/appsec/findings filters on orgId alone, with no isActive
 * predicate in the route or in lib/appsec/repo-filter.js. The repositories LIST route DID filter, so
 * the repo itself vanished from the UI while its findings stayed visible and counted — which is
 * exactly why nobody noticed. Measured on prod: 31 of 2,267 OPEN findings (1.4%) belonged to
 * shadow-span-deletion_scheduled-83523634, deactivated three weeks earlier.
 *
 * WHY `CLOSED` AND NOT `REMEDIATED`. The scanner's own stale-sweep uses REMEDIATED, which asserts the
 * problem was FIXED. Nothing was fixed here — we simply stopped being able to see it. CLOSED is the
 * neutral scanner-owned terminal state and was previously unused; this gives it its meaning.
 *
 * REVERSIBLE BY CONSTRUCTION. Analyst decisions are never touched (FALSE_POSITIVE / ACCEPTED_RISK
 * stay put), and upsertAppSecFindings now re-opens a re-observed CLOSED finding exactly as it does a
 * REMEDIATED one — so restoring a token or re-adding a repository brings its findings back on the
 * next scan rather than burying them for good.
 *
 * A RECONCILIATION SWEEP, not a hook on the deactivation event. Both discovery paths (GitHub App and
 * the shared GitLab/Bitbucket core) return only a COUNT of deactivated repos, and wiring IDs through
 * both would mean two places to remember. Sweeping instead is idempotent, costs one indexed query,
 * and — the reason it matters — heals repositories that were deactivated BEFORE this existed. The 31
 * prod findings above were three weeks stale; an event hook would never have touched them.
 *
 * @param {object} prisma
 * @param {{orgId: string}} args
 * @returns {Promise<{closed:number, repos:number}>}
 */
export async function closeFindingsForInactiveRepos(prisma, { orgId }) {
  if (!orgId) return { closed: 0, repos: 0 };
  const inactive = await prisma.sourceRepository.findMany({
    where: { organizationId: orgId, isActive: false },
    select: { id: true },
  });
  if (inactive.length === 0) return { closed: 0, repos: 0 };
  let closed = 0;
  for (const ids of chunk(inactive.map((r) => r.id))) {
    const r = await prisma.appSecFinding.updateMany({
      // Analyst decisions are untouched: FALSE_POSITIVE and ACCEPTED_RISK are deliberate verdicts
      // about the finding itself and survive the repository going away.
      where: { orgId, repositoryId: { in: ids }, status: { in: ['OPEN', 'IN_PROGRESS'] } },
      data: { status: 'CLOSED', fixedAt: new Date() },
    });
    closed += r.count;
  }
  return { closed, repos: inactive.length };
}
