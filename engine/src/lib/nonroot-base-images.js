/**
 * Base images that already run as a non-root user, so a Dockerfile using one needs no `USER`
 * directive of its own.
 *
 * WHY THIS EXISTS. Trivy's DS-0002 ("Image user should not be 'root'") reads only the instructions
 * in the Dockerfile — it does not resolve the base image's own config. A Dockerfile whose final
 * stage is `gcr.io/distroless/base-debian12:nonroot` therefore gets flagged HIGH even though the
 * image runs as uid 65532 and adding `USER` would change nothing. On our tree that was
 * services/ct-phishing/Dockerfile, which carries a comment saying exactly this and asking that the
 * scanner be fixed rather than the Dockerfile padded with a no-op line. This is that fix.
 *
 * Tag-based, deliberately. Resolving the truth would mean pulling each base image and reading its
 * config, which needs registry credentials and network inside the scanner — too much cost and too
 * much failure surface for one check. So this is a small, curated, *conservative* list: every entry
 * is a published convention where the tag itself is the vendor's guarantee of a non-root uid.
 *
 * Verified, not assumed:
 *   docker inspect gcr.io/distroless/base-debian12:nonroot --format '{{.Config.User}}'  -> 65532
 * Distroless documents the `:nonroot` variants as running under uid 65532:
 *   https://github.com/GoogleContainerTools/distroless#how-do-i-use-distroless-images
 * Chainguard images default to the non-root `nonroot` user:
 *   https://edu.chainguard.dev/chainguard/chainguard-images/about/images-compiled-programs/
 *
 * ADDING AN ENTRY IS A SECURITY DECISION. A wrong entry silently suppresses a real finding, which
 * is strictly worse than the false positive it was meant to remove. Only add an image whose
 * non-root user you have confirmed with `docker inspect`, and record the observation here.
 */

/** Patterns whose tag guarantees a non-root default user. */
const NONROOT_PATTERNS = [
  // Google distroless `:nonroot` / `:nonroot-<arch>` / `:debug-nonroot` variants -> uid 65532.
  /^gcr\.io\/distroless\/[^:\s]+:(?:[\w.-]+-)?nonroot(?:-[\w.]+)?$/i,
  // Chainguard images run as `nonroot` by default.
  /^cgr\.dev\/chainguard\/[^:\s]+(?::[\w.-]+)?$/i,
];

/**
 * The image reference of a Dockerfile's FINAL stage — the one that actually runs. Earlier stages
 * are build-time only and their user is irrelevant.
 *
 * @param {string} dockerfile  raw Dockerfile contents
 * @returns {string|null} the final FROM's image reference, or null if none parsed
 */
export function finalStageImage(dockerfile) {
  const froms = [...String(dockerfile || '').matchAll(/^\s*FROM\s+(?:--\S+\s+)*(\S+)/gim)];
  if (!froms.length) return null;
  const last = froms[froms.length - 1][1];
  return last.startsWith('$') ? null : last; // an ARG-templated base is unresolvable here
}

/**
 * Does this Dockerfile's final stage run as non-root without needing a USER directive?
 *
 * A `USER` appearing after the final FROM is handled by Trivy itself (it would not flag at all), so
 * this only answers the base-image half.
 *
 * @param {string} dockerfile  raw Dockerfile contents
 * @returns {boolean}
 */
export function finalStageIsNonRoot(dockerfile) {
  const image = finalStageImage(dockerfile);
  if (!image) return false; // unknown -> report the finding; never suppress on a guess
  return NONROOT_PATTERNS.some((re) => re.test(image));
}

/** Trivy check IDs that mean "no USER directive / runs as root". */
export const ROOT_USER_CHECK_IDS = new Set(['DS-0002', 'AVD-DS-0002']);
