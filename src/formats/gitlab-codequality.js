// GitLab Code Quality report emitter. Emit as a CI artifact
// (artifacts:reports:codequality) → findings render in the MR widget on ALL
// GitLab tiers, with NO token and NO API call. (The SAST-report widget needs
// Ultimate; Code Quality is universal, so it's our default GitLab native output.)

import { createHash } from 'node:crypto';

// GitLab Code Quality severities.
const GL_SEVERITY = { CRITICAL: 'blocker', HIGH: 'critical', MEDIUM: 'major', LOW: 'minor', UNKNOWN: 'info' };

export function toCodeQuality(findings = []) {
  return findings.map((f) => {
    // Stable fingerprint — prefer the engine identity key; else hash the tuple.
    const fingerprint = f.identityKey
      ? createHash('sha1').update(f.identityKey).digest('hex')
      : createHash('sha1').update(`${f.type}:${f.ruleId}:${f.file || ''}:${f.line || ''}`).digest('hex');
    return {
      description: `${f.ruleName || f.ruleId}${f.description ? ` — ${f.description}` : ''}`.slice(0, 1000),
      check_name: f.ruleId,
      fingerprint,
      severity: GL_SEVERITY[f.severity] || 'info',
      location: {
        path: f.file || '(repository)',
        lines: { begin: f.line || 1 },
      },
    };
  });
}
