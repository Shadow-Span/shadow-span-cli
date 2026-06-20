// Reporter dispatch — detect the CI platform from env, build its context, and
// route PR/MR feedback to the matching reporter. All best-effort; reporting
// never affects the gate exit code.

import * as github from './github.js';
import * as gitlab from './gitlab.js';
import * as bitbucket from './bitbucket.js';

const REPORTERS = { github, gitlab, bitbucket };

/** Identify the CI platform from environment markers. */
export function detectProvider(env = process.env) {
  if (env.GITHUB_ACTIONS) return 'github';
  if (env.GITLAB_CI) return 'gitlab';
  if (env.BITBUCKET_BUILD_NUMBER) return 'bitbucket';
  return null;
}

/** Resolve { provider, context } from env, or null if not in a usable PR/MR context. */
export function resolveContext(env = process.env) {
  const provider = detectProvider(env);
  if (!provider) return null;
  const ctx = REPORTERS[provider].contextFromEnv(env);
  return ctx ? { provider, ctx } : null;
}

/**
 * Post PR/MR feedback via the detected provider. Returns a result object (or
 * { skipped } when there's no usable context). Never throws.
 */
export async function postPrFeedback({ findings, gate, reportUrl, env = process.env, log = () => {} }) {
  const resolved = resolveContext(env);
  if (!resolved) {
    const p = detectProvider(env);
    return { skipped: p ? `${p}: missing PR/MR context or token` : 'no supported CI platform detected' };
  }
  try {
    return await REPORTERS[resolved.provider].post({ ctx: resolved.ctx, findings, gate, reportUrl, log });
  } catch (e) {
    return { provider: resolved.provider, error: e.message };
  }
}
