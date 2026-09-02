// @shadow-span/appsec-engine — barrel of the canonical AppSec kernel.
//
// Consumers:
//   - services/appsec (server scanner: runner.js, dast-runner.js)
//   - tools/shadow-span-cli (customer shift-left CLI — vendors this kernel)
//   - apps/web ingest API (normalize/upsert/gate reuse)
//
// One implementation, no duplicates (matcher-kernel discipline). Engines shell
// out to binaries on PATH (gitleaks/ast-grep/osv-scanner/trivy/nuclei); the
// Prisma client is injected into upsertAppSecFindings — the package has zero
// runtime dependencies.

// Engines
export { scanSca, collectDependencyLicenses } from './engines/osv-scanner.js';
export { scanSecrets } from './engines/gitleaks.js';
export { scanSast } from './engines/sast.js';
export { scanIac } from './engines/iac.js';
export { scanBicep, isBicepAvailable } from './engines/bicep.js';
export { scanCicd, scanWorkflowText } from './engines/cicd.js';
export { scanContainer } from './engines/container.js';
export { scanDast } from './engines/nuclei.js';
export { scanZap, isZapAvailable } from './engines/zap.js';
export { generateSbom } from './engines/sbom.js';

// License policy gates (SBOM license → LICENSE findings)
export { evaluateLicensePolicy, classifyLicense, DEFAULT_LICENSE_POLICY } from './license-policy.js';

// Scanner ignore rules (settings page): path exclusions
export { applyPathExclusions, compileExclusions, isPathExcluded, explainExclusions, DEFAULT_EXCLUSIONS } from './lib/path-exclude.js';

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
  enrichDependencyDepth,
} from './lib/reachability.js';
export { isDockerfileName, findDockerfiles } from './lib/dockerfiles.js';

// Persistence (Prisma client injected)
export { upsertAppSecFindings, upsertRepoPackages, closeFindingsForInactiveRepos } from './findings.js';

// CI/pre-commit gate
export { evaluateGate, SEVERITY_ORDER, FAIL_ON_LEVELS } from './gate.js';

// Secret redaction (snippet + evidence scrubbing)
export { redactSecrets, redactSecretsPreservingLines, redactDeep, sanitizeForLog } from './redact.js';

// Suppression rules (read-time FP triage — org/repo scoped, MALWARE-exempt)
export {
  SUPPRESSION_SCOPES, SUPPRESSION_MATCH_TYPES,
  isRuleActive, findingMatchesRule, isSuppressed, buildSuppressionWhere,
  pathMatchesGlob, globToRegExp,
} from './suppression.js';

// Repo-local suppression file — the CLI's equivalent of the platform's rule rows.
export {
  SUPPRESSION_FILENAME, parseSuppressionFile, loadSuppressionFile, applySuppressions,
} from './suppression-file.js';

// Engine preflight — prove each scanner can run before trusting a clean result.
export { preflight, probeEngine, formatPreflightFailure, environmentInfo, ENGINE_BINARIES } from './preflight.js';
