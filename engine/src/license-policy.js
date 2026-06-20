// License policy gates — turn SBOM license data into AppSecFinding(type=LICENSE)
// rows so a disallowed/restricted dependency license flows through the SAME
// findings UI (filters, tickets, export, dismiss) and CLI gate as every other
// finding. No new surface, no new pipeline.
//
// Default policy: strong/network copyleft (GPL / AGPL / SSPL / OSL / EUPL) is
// DENY (HIGH); weak copyleft (LGPL / MPL / EPL / CDDL / MS-RL / CPL) is FLAG
// (MEDIUM); everything permissive (MIT / Apache / BSD / ISC …) is ALLOW. Orgs
// override via Organization.appSecLicensePolicy (JSON) — null = this default.
//
// SPDX expression aware: "MIT OR GPL-3.0" resolves to the MOST PERMISSIVE option
// (you may pick MIT → allow); "A AND B" resolves to the MOST RESTRICTIVE. The OR
// split is on the SPACED operator only, so the SPDX id "GPL-3.0-or-later" is NOT
// mis-split on its embedded "or".
//
// Org override lives on Subscription.appSecLicensePolicy (alongside modAppSec);
// the server runner loads it and passes it in. null = this default.

import { FINDING_TYPES } from './normalize.js';

export const DEFAULT_LICENSE_POLICY = Object.freeze({
  // Substring tokens matched on the normalized (upper-cased) SPDX id / name.
  deny: ['AGPL', 'GPL', 'SSPL', 'OSL', 'EUPL'], // strong / network copyleft
  flag: ['LGPL', 'MPL', 'EPL', 'CDDL', 'MS-RL', 'CPL'], // weak copyleft — review
  flagUnknown: false, // when true, packages with no detected license also flag
});

const SEVERITY_BY_KIND = { deny: 'HIGH', flag: 'MEDIUM' };
const RANK = { allow: 0, unknown: 1, flag: 2, deny: 3 };

function norm(s) {
  return String(s || '').toUpperCase().trim();
}

// Classify ONE atomic license (no AND/OR) against the policy. LGPL/MPL/etc. are
// checked BEFORE the GPL deny token because 'GPL' is a substring of 'LGPL' — a
// weak-copyleft hit must win so LGPL doesn't fall through to DENY.
function classifyAtom(token, policy) {
  const u = norm(token);
  if (!u) return 'unknown';
  if ((policy.flag || []).some((t) => u.includes(t))) return 'flag';
  if ((policy.deny || []).some((t) => u.includes(t))) return 'deny';
  return 'allow';
}

/**
 * Classify a full license expression. OR → most-permissive (min rank); AND →
 * most-restrictive (max rank); bare token → classifyAtom.
 * @returns {'allow'|'flag'|'deny'|'unknown'}
 */
export function classifyLicense(expr, policy = DEFAULT_LICENSE_POLICY) {
  const u = norm(expr);
  if (!u) return 'unknown';
  const clean = u.replace(/[()]/g, ' ');
  // Spaced operators only — never split the SPDX suffix "-OR-LATER".
  if (/\sOR\s/.test(clean)) {
    return clean.split(/\s+OR\s+/).map((p) => classifyLicense(p, policy))
      .reduce((best, c) => (RANK[c] < RANK[best] ? c : best), 'deny');
  }
  if (/\sAND\s/.test(clean)) {
    return clean.split(/\s+AND\s+/).map((p) => classifyLicense(p, policy))
      .reduce((worst, c) => (RANK[c] > RANK[worst] ? c : worst), 'allow');
  }
  return classifyAtom(clean, policy);
}

function spdxSlug(license) {
  const u = norm(license).replace(/[^A-Z0-9.+\- ]/g, '').trim().replace(/\s+/g, '-');
  return u.slice(0, 48) || 'UNKNOWN';
}

/**
 * Build normalized LICENSE finding rows from SBOM packages.
 * @param {Array}  packages  parseCycloneDxComponents rows ({purl,name,version,ecosystem,license})
 * @param {object} [policy]  org override; merged over DEFAULT_LICENSE_POLICY
 * @returns {Array} normalize.js-shaped finding rows (type=LICENSE)
 */
export function evaluateLicensePolicy(packages, policy) {
  const p = { ...DEFAULT_LICENSE_POLICY, ...(policy || {}) };
  const out = [];
  for (const pkg of packages || []) {
    const decision = classifyLicense(pkg.license, p);
    const isViolation =
      decision === 'deny' || decision === 'flag' || (decision === 'unknown' && p.flagUnknown);
    if (!isViolation) continue;

    const kind = decision === 'unknown' ? 'flag' : decision;
    const slug = decision === 'unknown' ? 'UNKNOWN' : spdxSlug(pkg.license);
    const ruleId = `LICENSE-${slug}`;
    const ver = pkg.version || '?';
    out.push({
      type: FINDING_TYPES.LICENSE,
      ruleId,
      ruleName:
        decision === 'deny' ? `Disallowed license: ${pkg.license}`
          : decision === 'unknown' ? `Unknown license: ${pkg.name}`
            : `Restricted license: ${pkg.license}`,
      severity: SEVERITY_BY_KIND[kind] || 'MEDIUM',
      file: null,
      line: null,
      column: null,
      description:
        decision === 'unknown'
          ? `${pkg.name}@${ver} has no detected license. Verify its terms before distributing.`
          : `${pkg.name}@${ver} is licensed under ${pkg.license} — ${decision === 'deny'
            ? 'strong/network copyleft, disallowed by policy.'
            : 'restricted copyleft, review required for your distribution model.'}`,
      remediation:
        decision === 'deny'
          ? `Replace ${pkg.name} with an equivalent under a permissive license (MIT / Apache-2.0 / BSD), or record a written policy exception.`
          : `Confirm the ${pkg.license || 'license'} obligations are acceptable, or replace ${pkg.name}.`,
      cveId: null,
      packageName: pkg.name,
      packageEcosystem: pkg.ecosystem,
      packageVersion: pkg.version,
      fixedVersion: null,
      cwe: null,
      // No file for an SBOM package → key on purl so it's stable across re-scans.
      identityKey: `${FINDING_TYPES.LICENSE}:${ruleId}:${pkg.purl || pkg.name}`,
      evidence: { license: pkg.license || null, purl: pkg.purl || null, policy: decision },
    });
  }
  return out;
}
