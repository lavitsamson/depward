// Range and dist-tag resolution against a packument, following the choice order of
// npm's own resolver (npm-pick-manifest, https://github.com/npm/npm-pick-manifest):
// a dist-tag names its version; for a range, the `latest` tag wins when it satisfies the
// range, otherwise the highest satisfying version, preferring non-deprecated ones.
// Engines and platform filtering are not applied: the gate checks what *would* be
// installed by default, and those rarely change the pick.

import { semver } from "../lazy.ts";
import type { Packument, VersionMeta } from "./types.ts";

/** Options for {@link resolveVersion}. */
export interface ResolveOptions {
  /**
   * Only consider versions published at or before this time (milliseconds since the
   * epoch). Versions with no valid publish time in `packument.time` are excluded.
   */
  publishedBefore?: number;
}

/** Publish time of `version` in milliseconds, or `null` if the packument has none. */
export function publishTime(packument: Packument, version: string): number | null {
  if (!Object.hasOwn(packument.time, version)) return null;
  const ms = Date.parse(packument.time[version] ?? "");
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Picks the version that `npm install name@spec` would install, or `null` when nothing
 * matches. `spec` is a dist-tag, an exact version, or a semver range; `""` and `*` mean
 * "latest". Ranges are parsed loosely, as npm does.
 */
export function resolveVersion(packument: Packument, spec: string, opts: ResolveOptions = {}): VersionMeta | null {
  const { versions } = packument;
  const tags = packument["dist-tags"];
  const cutoff = opts.publishedBefore;
  const eligible = (v: string): boolean => {
    if (!Object.hasOwn(versions, v)) return false;
    if (cutoff === undefined) return true;
    const at = publishTime(packument, v);
    return at !== null && at <= cutoff;
  };

  const wanted = spec.trim() === "" ? "*" : spec.trim();
  // npm refuses dist-tags that are valid ranges, so a tag name never shadows a range.
  if (Object.hasOwn(tags, wanted) && semver().validRange(wanted, { loose: true }) === null) {
    const target = tags[wanted];
    return target !== undefined && eligible(target) ? (versions[target] ?? null) : null;
  }
  if (semver().validRange(wanted, { loose: true }) === null) return null;

  const latest = Object.hasOwn(tags, "latest") ? tags["latest"] : undefined;
  if (latest !== undefined && eligible(latest) && semver().satisfies(latest, wanted, { loose: true })) {
    return versions[latest] ?? null;
  }

  let best: VersionMeta | null = null;
  for (const v of Object.keys(versions)) {
    if (!eligible(v) || semver().valid(v, { loose: true }) === null || !semver().satisfies(v, wanted, { loose: true })) continue;
    const meta = versions[v];
    if (meta === undefined) continue;
    if (best === null || better(meta, best)) best = meta;
  }
  return best;
}

function better(a: VersionMeta, b: VersionMeta): boolean {
  const aDep = isDeprecated(a);
  const bDep = isDeprecated(b);
  if (aDep !== bDep) return bDep;
  return semver().gt(a.version, b.version, { loose: true });
}

/** True for a valid semver version with a prerelease tag (`1.0.0-beta.1`). */
export function isPrerelease(version: string): boolean {
  return (semver().prerelease(version, { loose: true })?.length ?? 0) > 0;
}

/** True when the version carries a non-empty `deprecated` message. */
export function isDeprecated(meta: VersionMeta): boolean {
  return typeof meta.deprecated === "string" && meta.deprecated !== "";
}
