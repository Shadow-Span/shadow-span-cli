// Shadow Span AppSec engine — barrel of the scanning kernel.
//
// Engines shell out to binaries on PATH (gitleaks / ast-grep / osv-scanner /
// trivy / nuclei) and normalize their output into a single finding format. A
// database client is injected into upsertAppSecFindings when persistence is
// needed — the kernel itself has zero runtime dependencies.

// Engines
export { scanSca, collectDependencyLicenses } from './engines/osv-scanner.js';
export { scanSecrets } from './engines/gitleaks.js';
export { scanSast } from './engines/sast.js';
export { scanIac } from './engines/iac.js';
export { scanCicd, scanWorkflowText } from './engines/cicd.js';
export { scanContainer } from './engines/container.js';
export { scanDast } from './engines/nuclei.js';
export { scanZap, isZapAvailable } from './engines/zap.js';
export { generateSbom } from './engines/sbom.js';

// License policy gates (SBOM license → LICENSE findings)
export { evaluateLicensePolicy, classifyLicense, DEFAULT_LICENSE_POLICY } from './license-policy.js';

// Scanner ignore rules (settings page): path exclusions
export { applyPathExclusions, compileExclusions, isPathExcluded } from './lib/path-exclude.js';

// Normalization + finding identity
export {
  FINDING_TYPES,
  normalizeSeverityWord,
  cvssScoreToSeverity,
  buildIdentityKey,
  suggestSastFix,
  normalizeOsvResults,
  normalizeGitleaksResults,
  normalizeAstGrepResults,
  normalizeTrivyConfigResults,
  parseDockerfileFromImages,
  normalizeTrivyImageResults,
  normalizeNucleiResults,
  normalizeZapResults,
  parseCycloneDxComponents,
} from './normalize.js';

// Enrichment helpers
export { attachCodeContext } from './code-context.js';
export { attachBlame, parseBlamePorcelain } from './git-blame.js';
export {
  parseNpmDirect,
  parseGoModDirect,
  parsePyDirect,
  enrichReachability,
} from './lib/reachability.js';
export { isDockerfileName, findDockerfiles } from './lib/dockerfiles.js';

// Persistence (Prisma client injected)
export { upsertAppSecFindings, upsertRepoPackages } from './findings.js';

// CI/pre-commit gate
export { evaluateGate, SEVERITY_ORDER, FAIL_ON_LEVELS } from './gate.js';

// Secret redaction (snippet + evidence scrubbing)
export { redactSecrets, redactDeep } from './redact.js';
