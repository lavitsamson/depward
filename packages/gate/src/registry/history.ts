// Checks that compare a version against the package's publish history: who published
// it, who maintains it, and whether it lost provenance. Pure functions over a packument.
// "Previous" always means earlier by publish time (`packument.time`), not by semver, so
// a backport published last is compared with what was published just before it.

import { isPrerelease, publishTime, type Packument, type Person, type VersionMeta } from "@depward/core";

/** How many earlier versions `publisher-changed` and `provenance-dropped` look at. */
export const HISTORY_WINDOW = 5;

const DAY = 86_400_000;

/**
 * Versions published before `version`, newest first, optionally only those that pass
 * `keep`. Versions without a time are skipped.
 */
export function previousVersions(
  packument: Packument,
  version: string,
  limit: number = HISTORY_WINDOW,
  keep: (meta: VersionMeta) => boolean = () => true,
): VersionMeta[] {
  const at = publishTime(packument, version);
  if (at === null) return [];
  return timed(packument)
    .filter((t) => t.at < at && t.meta.version !== version && keep(t.meta))
    .toSorted((a, b) => b.at - a.at)
    .slice(0, limit)
    .map((t) => t.meta);
}

function timed(packument: Packument): { meta: VersionMeta; at: number }[] {
  const out: { meta: VersionMeta; at: number }[] = [];
  for (const [v, meta] of Object.entries(packument.versions)) {
    const at = publishTime(packument, v);
    if (at !== null) out.push({ meta, at });
  }
  return out;
}

function personName(p: Person | undefined): string | null {
  return typeof p === "object" && p !== null && typeof p.name === "string" && p.name !== "" ? p.name : null;
}

function maintainerNames(meta: VersionMeta): Set<string> | null {
  if (!Array.isArray(meta.maintainers)) return null;
  const names = new Set<string>();
  for (const m of meta.maintainers) {
    const n = personName(m);
    if (n !== null) names.add(n);
  }
  return names;
}

/** True when the version's `dist` advertises attestations. */
export function hasAttestations(meta: VersionMeta): boolean {
  const a: unknown = meta.dist.attestations;
  return typeof a === "object" && a !== null && typeof (a as { url?: unknown }).url === "string";
}

/** Result of {@link publisherChange}. */
export interface PublisherChange {
  /** `_npmUser.name` of the checked version. */
  readonly publisher: string;
  /** Distinct publishers of the previous versions, newest first. */
  readonly previous: readonly string[];
}

/** A maintainer counts as established once listed this many days before a publish. */
export const ESTABLISHED_MAINTAINER_DAYS = 30;

/** `publisher-changed` ignores versions published longer ago than this (when given a clock). */
export const PUBLISHER_CHANGE_MAX_AGE_DAYS = 90;

/**
 * True when the version was published through npm trusted publishing (OIDC) and has a
 * provenance attestation. The registry sets `_npmUser` itself, adding
 * `trustedPublisher: { id: "github" | …, oidcConfigId }` to such publishes (observed on
 * registry.npmjs.org, 2026-11-11: es-module-lexer@3.0.4, tar@7.5.23; trusted publishing
 * generates provenance, https://docs.npmjs.com/trusted-publishers). A name or email
 * alone is never enough: an ordinary account can be called "GitHub Actions".
 */
export function isTrustedPublish(meta: VersionMeta): boolean {
  const user: unknown = meta._npmUser;
  if (typeof user !== "object" || user === null) return false;
  const tp: unknown = (user as { trustedPublisher?: unknown }).trustedPublisher;
  if (typeof tp !== "object" || tp === null || typeof (tp as { id?: unknown }).id !== "string") return false;
  const provenance: unknown = (meta.dist.attestations as { provenance?: unknown } | undefined)?.provenance;
  return hasAttestations(meta) && typeof provenance === "object" && provenance !== null;
}

/**
 * `publisher-changed`: the version's `_npmUser` did not publish any of the previous
 * {@link HISTORY_WINDOW} versions and is not an established maintainer. `null`
 * otherwise, or when there is no history to compare with.
 *
 * Established means listed in the `maintainers` of the version just before this one
 * *and* of the newest version published at least {@link ESTABLISHED_MAINTAINER_DAYS}
 * days before it. Each version records its maintainers as they were at publish time,
 * so an account an attacker added recently never qualifies, even if a release in
 * between already lists it. A long-standing maintainer publishing for the first time
 * (a team member, or a CI account) is not flagged.
 *
 * Also not flagged (approved 2026-11-11 after the top-1,000 benchmark):
 * - a version published through npm trusted publishing with a provenance attestation
 *   ({@link isTrustedPublish}). Moving to OIDC publishing replaces the person in
 *   `_npmUser` with the CI identity, and a maintainer has to set it up on npmjs.com.
 * - with `now`, a version published more than {@link PUBLISHER_CHANGE_MAX_AGE_DAYS} days
 *   ago: a takeover shows up in a fresh release, and an old one has been in use since.
 */
export function publisherChange(packument: Packument, meta: VersionMeta, opts: { now?: number } = {}): PublisherChange | null {
  const publisher = personName(meta._npmUser);
  if (publisher === null || isTrustedPublish(meta)) return null;
  if (opts.now !== undefined) {
    const at = publishTime(packument, meta.version);
    if (at !== null && opts.now - at > PUBLISHER_CHANGE_MAX_AGE_DAYS * DAY) return null;
  }
  const history = previousVersions(packument, meta.version);
  const previous = [...new Set(history.map((m) => personName(m._npmUser)).filter((n) => n !== null))];
  if (previous.length === 0 || previous.includes(publisher)) return null;
  return isEstablishedMaintainer(packument, meta, publisher, history[0]) ? null : { publisher, previous };
}

function isEstablishedMaintainer(packument: Packument, meta: VersionMeta, name: string, last: VersionMeta | undefined): boolean {
  const at = publishTime(packument, meta.version);
  if (at === null || last === undefined || !maintainerNames(last)?.has(name)) return false;
  const cutoff = at - ESTABLISHED_MAINTAINER_DAYS * DAY;
  const baseline = timed(packument)
    .filter((t) => t.at <= cutoff)
    .toSorted((a, b) => b.at - a.at)[0];
  return baseline !== undefined && maintainerNames(baseline.meta)?.has(name) === true;
}

/** A maintainer who first appears in a recently published version. */
export interface AddedMaintainer {
  readonly name: string;
  /** The first recent version that lists them. */
  readonly version: string;
}

/**
 * `maintainer-added-recently`: maintainers listed on versions published within the
 * last `days` days who are not listed on the newest version published before that
 * window. Empty when the package has no version older than the window (it is new,
 * which `package-too-new` covers) or when that version records no maintainers.
 */
export function addedMaintainers(packument: Packument, now: number, days: number = 30): AddedMaintainer[] {
  const cutoff = now - days * DAY;
  const all = timed(packument).toSorted((a, b) => a.at - b.at);
  const baseline = all.filter((t) => t.at < cutoff).at(-1);
  const known = baseline ? maintainerNames(baseline.meta) : null;
  if (known === null) return [];
  const added: AddedMaintainer[] = [];
  for (const t of all) {
    if (t.at < cutoff || t.at > now) continue;
    for (const name of maintainerNames(t.meta) ?? []) {
      if (known.has(name)) continue;
      known.add(name);
      added.push({ name, version: t.meta.version });
    }
  }
  return added;
}

/**
 * `provenance-dropped`: the version has no attestations, but one of the previous
 * {@link HISTORY_WINDOW} versions did. Returns that earlier version, or `null`.
 *
 * A stable version is compared only with earlier stable versions: projects often build
 * prereleases (`8.0.0-alpha.14`) on a different pipeline than their stable line, and a
 * stable line that never had provenance hasn't dropped it. A prerelease is compared
 * with every earlier version, so dropping provenance on either line is still caught.
 */
export function provenanceDrop(packument: Packument, meta: VersionMeta): VersionMeta | null {
  if (hasAttestations(meta)) return null;
  const sameLine = isPrerelease(meta.version) ? () => true : (m: VersionMeta) => !isPrerelease(m.version);
  return previousVersions(packument, meta.version, HISTORY_WINDOW, sameLine).find(hasAttestations) ?? null;
}
