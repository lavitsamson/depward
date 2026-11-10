// Typosquat detection against the popular-packages list (data/popular-packages.json).
// Spec: docs/specs/gate.md §Registry checks, `typosquat-suspect`.

import { editDistance } from "./edit-distance.ts";

/** One entry of the popular-packages list. */
export interface PopularPackage {
  readonly name: string;
  readonly weeklyDownloads: number;
}

/** Why a name looks like a popular one. */
export type SimilarityKind = "edit-distance" | "separator" | "scope";

/** A popular package whose name is close to the one being checked. */
export interface SimilarPackage extends PopularPackage {
  readonly kind: SimilarityKind;
  /** Edit distance ({@link editDistance}) between the two names. */
  readonly distance: number;
}

/** Lookup structure over the popular-packages list. */
export interface PopularIndex {
  /** Number of packages in the list. */
  readonly size: number;
  /** Weekly downloads of a listed package, or `undefined` if it is not listed. */
  downloads(name: string): number | undefined;
  /**
   * Listed packages whose names are close to `name`: closest first, then most
   * downloaded. Packages in the same scope as `name` are skipped, because only the
   * scope's owner can publish there, so they can't be a third party's typosquat.
   */
  similar(name: string): SimilarPackage[];
}

/** Names of this many characters or fewer only match at edit distance 1. */
export const SHORT_NAME_LENGTH = 5;

/** Folds case, scope markers, and separators: `@Foo/bar_baz.js` → `foobarbazjs`. */
export function separatorKey(name: string): string {
  return name.toLowerCase().replace(/[@/._-]/g, "");
}

function scopeOf(name: string): string | null {
  return name.startsWith("@") && name.includes("/") ? name.slice(0, name.indexOf("/")).toLowerCase() : null;
}

/** Maximum edit distance at which `target` (a popular name) counts as similar. */
export function maxDistanceFor(target: string): number {
  return target.length <= SHORT_NAME_LENGTH ? 1 : 2;
}

/** Builds a {@link PopularIndex}. Later duplicates of a name are ignored. */
export function createPopularIndex(packages: readonly PopularPackage[]): PopularIndex {
  const byName = new Map<string, PopularPackage>();
  const byLength = new Map<number, PopularPackage[]>();
  const byKey = new Map<string, PopularPackage[]>();
  for (const p of packages) {
    const name = p.name.toLowerCase();
    if (byName.has(name)) continue;
    const entry = { name, weeklyDownloads: p.weeklyDownloads };
    byName.set(name, entry);
    push(byLength, name.length, entry);
    push(byKey, separatorKey(name), entry);
  }

  return {
    size: byName.size,
    downloads: (name) => byName.get(name.toLowerCase())?.weeklyDownloads,
    similar(input) {
      const name = input.toLowerCase();
      const scope = scopeOf(name);
      const found = new Map<string, SimilarPackage>();
      const consider = (p: PopularPackage, kind: SimilarityKind, distance: number): void => {
        if (p.name === name || (scope !== null && scopeOf(p.name) === scope)) return;
        const prev = found.get(p.name);
        if (prev === undefined || distance < prev.distance) found.set(p.name, { ...p, kind, distance });
      };

      for (const p of byKey.get(separatorKey(name)) ?? []) {
        // Same-scope names are skipped in consider(), so a scoped side means a scope swap.
        consider(p, scope === null && scopeOf(p.name) === null ? "separator" : "scope", editDistance(name, p.name));
      }
      for (let len = name.length - 2; len <= name.length + 2; len++) {
        for (const p of byLength.get(len) ?? []) {
          const max = maxDistanceFor(p.name);
          const d = editDistance(name, p.name, max);
          if (d <= max) consider(p, "edit-distance", d);
        }
      }
      return [...found.values()].toSorted(
        (a, b) => a.distance - b.distance || b.weeklyDownloads - a.weeklyDownloads || (a.name < b.name ? -1 : 1),
      );
    },
  };
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}
