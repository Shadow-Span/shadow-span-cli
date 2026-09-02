/**
 * Engine preflight — prove every requested scanner can actually run, BEFORE scanning.
 *
 * WHY. A missing engine binary used to produce a green check. `runEngines` collects per-engine
 * failures into `errors`, and the CLI only exited non-zero when EVERY engine failed
 * (`errors.length === engines.length`). So on a machine without gitleaks:
 *
 *     ✓ No findings.
 *     ⚠ 1 engine error(s): secret
 *     ✓ Gate passed (fail-on: high).      <- exit 0
 *
 * ...on a repository containing a live GitHub token. Measured, not theorised: the binary was moved
 * aside inside the real action image and the CLI run end to end.
 *
 * CAPABILITY, NOT OS. It is tempting to branch on `process.platform`, and that would have caught the
 * `grep -qP` failure that started this. But the OS is a PROXY for the fact you need: macOS with GNU
 * coreutils on PATH behaves like Linux, Alpine's busybox differs from GNU *on* Linux, and a
 * container may ship a binary the host lacks. So this probes the tool itself — run it, see if it
 * answers — and records the OS only as CONTEXT for the error message. The platform is what you tell
 * a human to help them fix it; the probe is what you trust.
 *
 * FAIL LOUD. Every failure this codebase found today shared one shape: a check could not run, and
 * silence was read as success. A preflight that returns "unknown" and lets the scan proceed would be
 * the same bug wearing a different hat.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';

const execFileAsync = promisify(execFile);

/** Probe timeout. Generous — a cold binary on a loaded CI runner can be slow — but bounded. */
const PROBE_TIMEOUT_MS = parseInt(process.env.APPSEC_PREFLIGHT_TIMEOUT_MS || '15000', 10);

/**
 * Engine key -> the binary it shells out to.
 *
 * Resolved through the SAME env overrides the engines themselves use, so preflight can never probe
 * a different binary than the one that will run. Reading the override here and not there (or vice
 * versa) would make the preflight a lie.
 */
export const ENGINE_BINARIES = Object.freeze({
  secret: { name: () => 'gitleaks', args: ['version'] },
  sca: { name: () => 'osv-scanner', args: ['--version'] },
  sast: { name: () => process.env.APPSEC_ASTGREP_BIN || 'ast-grep', args: ['--version'] },
  iac: { name: () => process.env.APPSEC_TRIVY_BIN || 'trivy', args: ['--version'] },
  // DAST tiers are optional and already degrade gracefully (see engines/zap.js), so they are not
  // preflighted here — a missing ZAP is a documented "not installed", not a silent clean result.
});

/** Environment context. Diagnostic only — never used to decide whether a tool works. */
export function environmentInfo(env = process.env) {
  return {
    platform: process.platform,          // darwin | linux | win32
    arch: process.arch,
    release: os.release(),
    node: process.version,
    // Which shell a child_process would get. Relevant because the same command can resolve a
    // different binary under bash vs an interactive zsh — that is exactly how a broken `grep -P`
    // hook looked healthy when spot-checked by hand.
    shell: env.SHELL || '(unknown)',
    inContainer: Boolean(env.GITHUB_WORKSPACE) || env.APPSEC_IN_CONTAINER === 'true',
  };
}

/**
 * Probe one binary.
 * @returns {Promise<{engine:string, binary:string, ok:boolean, version?:string, reason?:string}>}
 */
export async function probeEngine(engine) {
  const spec = ENGINE_BINARIES[engine];
  if (!spec) return { engine, binary: '(unknown)', ok: false, reason: `no binary mapping for engine '${engine}'` };
  const binary = spec.name();
  try {
    const { stdout, stderr } = await execFileAsync(binary, spec.args, { timeout: PROBE_TIMEOUT_MS });
    const version = String(stdout || stderr || '').trim().split('\n')[0] || '(no version output)';
    return { engine, binary, ok: true, version };
  } catch (err) {
    // ENOENT is the common case (not installed / not on PATH). Anything else — a non-zero exit, a
    // timeout, a dynamic-linker failure — is equally disqualifying: if it cannot report its own
    // version it cannot be trusted to report findings.
    const reason = err.code === 'ENOENT'
      ? `not found on PATH`
      : `failed to run (${err.code ?? 'error'}): ${String(err.stderr || err.message).trim().split('\n')[0]}`;
    return { engine, binary, ok: false, reason };
  }
}

/**
 * Preflight the requested engines.
 *
 * @param {string[]} engines
 * @returns {Promise<{ok:boolean, environment:object, results:Array, missing:Array}>}
 */
export async function preflight(engines = []) {
  const results = await Promise.all(engines.map((e) => probeEngine(e)));
  const missing = results.filter((r) => !r.ok);
  return { ok: missing.length === 0, environment: environmentInfo(), results, missing };
}

/**
 * Human-readable failure text. Names the platform because that is what an install hint depends on —
 * the OS informs the ADVICE, never the verdict.
 */
export function formatPreflightFailure({ environment, missing }) {
  const hint = {
    darwin: 'brew install',
    linux: 'your package manager, or the release binary from the project',
    win32: 'scoop/choco, or the release binary from the project',
  }[environment.platform] || 'your package manager';

  const lines = [
    `Cannot scan: ${missing.length} required engine binar${missing.length === 1 ? 'y is' : 'ies are'} unavailable.`,
    '',
    ...missing.map((m) => `  ${m.engine.padEnd(7)} needs '${m.binary}' — ${m.reason}`),
    '',
    `Install with ${hint}, or point the scan at a different binary via the APPSEC_*_BIN variables.`,
    `Environment: ${environment.platform}/${environment.arch}, node ${environment.node}, shell ${environment.shell}`,
    '',
    'Refusing to continue: a scan missing an engine cannot honestly report "no findings".',
  ];
  return lines.join('\n');
}
