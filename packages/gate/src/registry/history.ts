// Checks that compare a version against the package's publish history: who published
// it, who maintains it, and whether it lost provenance. Pure functions over a packument.
// "Previous" always means earlier by publish time (`packument.time`), not by semver, so
// a backport published last is compared with what was published just before it.

import { publishTime, type Packument, type Person, type VersionMeta } from "@depward/core";

/** How many earlier versions `publisher-changed` and `provenance-dropped` look at. */
export const HISTORY_WINDOW = 5;

const DAY = 86_400_000;

/** Versions published before `version`, newest first. Versions without a time are skipped. */
export function previousVersions(packument: Packument, version: string, limit: number = HISTORY_WINDOW): VersionMeta[] {
  const at = publishTime(packument, version);
  if (at === null) return [];
  return timed(packument)
    .filter((t) => t.at < at && t.meta.version !== version)
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

/**
 * `publisher-changed`: the version's `_npmUser` is not among the publishers of the
 * previous {@link HISTORY_WINDOW} versions. `null` when it is, or when there is no
 * history to compare with.
 */
export function publisherChange(packument: Packument, meta: VersionMeta): PublisherChange | null {
  const publisher = personName(meta._npmUser);
  if (publisher === null) return null;
  const previous = [...new Set(previousVersions(packument, meta.version).map((m) => personName(m._npmUser)).filter((n) => n !== null))];
  if (previous.length === 0 || previous.includes(publisher)) return null;
  return { publisher, previous };
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
 */
export function provenanceDrop(packument: Packument, meta: VersionMeta): VersionMeta | null {
  if (hasAttestations(meta)) return null;
  return previousVersions(packument, meta.version).find(hasAttestations) ?? null;
}
