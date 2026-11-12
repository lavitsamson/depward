// The raw deltas between two package profiles and their version metadata. Pure set
// arithmetic, with no judgement: rules.ts turns these into findings.
// Spec: docs/specs/diff.md § Delta rules.

import { CAPABILITIES, type Capability, type PackageProfile, type Signal } from "@depward/analyzer";
import { hasAttestations, type VersionMeta } from "@depward/core";
import type { PackageDiff, ScriptChange } from "./types.ts";

/** Scripts compared by {@link scriptDelta}, in this order. */
export const SCRIPT_NAMES = ["preinstall", "install", "postinstall", "prepare"] as const;

/** A file counts as changed a lot when its size moves by more than this fraction… */
export const LARGE_CHANGE_RATIO: number = 0.5;
/** …or by more than this many bytes. */
export const LARGE_CHANGE_BYTES: number = 100 * 1024;

// Code-unit order, so output does not depend on the machine's locale.
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function minus(a: Iterable<string>, b: Iterable<string>): string[] {
  const drop = new Set(b);
  return [...new Set([...a].filter((x) => !drop.has(x)))].toSorted(byCodeUnit);
}

const used = (p: PackageProfile): Set<Capability> => new Set(CAPABILITIES.filter((c) => p.capabilities[c].length > 0));

/** Capabilities used in B and not in A, and the reverse, in {@link CAPABILITIES} order. */
export function capabilityDelta(a: PackageProfile, b: PackageProfile): PackageDiff["capabilityDelta"] {
  const inA = used(a);
  const inB = used(b);
  return { added: CAPABILITIES.filter((c) => inB.has(c) && !inA.has(c)), removed: CAPABILITIES.filter((c) => inA.has(c) && !inB.has(c)) };
}

/** Signals compared by id: every signal of one side whose id the other side lacks. */
export function signalDelta(a: PackageProfile, b: PackageProfile): PackageDiff["signalDelta"] {
  return { added: signalsNotIn(b, signalIds(a)), removed: signalsNotIn(a, signalIds(b)) };
}

const signalIds = (p: PackageProfile): Set<string> => new Set(p.signals.map((s) => s.id));
const signalsNotIn = (p: PackageProfile, ids: Set<string>): Signal[] => p.signals.filter((s) => !ids.has(s.id));

/** Install scripts whose command differs (including appearing or disappearing). */
export function scriptDelta(a: PackageProfile, b: PackageProfile): Record<string, ScriptChange> {
  const out: Record<string, ScriptChange> = {};
  for (const name of SCRIPT_NAMES) {
    const from = a.scripts[name];
    const to = b.scripts[name];
    if (from === to) continue;
    out[name] = { ...(from === undefined ? {} : { from }), ...(to === undefined ? {} : { to }) };
  }
  return out;
}

/**
 * Declared dependencies (`dependencies`, then `optionalDependencies`, then
 * `peerDependencies`; the first one wins for a name). Only string ranges count.
 */
export function declaredDependencies(meta: VersionMeta): Map<string, string> {
  const out = new Map<string, string>();
  for (const group of [meta.dependencies, meta.optionalDependencies, meta.peerDependencies]) {
    if (typeof group !== "object" || group === null) continue;
    for (const [name, range] of Object.entries(group)) {
      if (typeof range === "string" && !out.has(name)) out.set(name, range);
    }
  }
  return out;
}

/** Dependency names added, removed, or with a changed range. */
export function dependencyDelta(metaA: VersionMeta, metaB: VersionMeta): PackageDiff["dependencyDelta"] {
  const a = declaredDependencies(metaA);
  const b = declaredDependencies(metaB);
  return {
    added: minus(b.keys(), a.keys()),
    removed: minus(a.keys(), b.keys()),
    changed: [...b.keys()].filter((n) => a.has(n) && a.get(n) !== b.get(n)).toSorted(byCodeUnit),
  };
}

/** True when a file's size moved by more than {@link LARGE_CHANGE_RATIO} or {@link LARGE_CHANGE_BYTES}. */
export function isLargeChange(sizeA: number, sizeB: number): boolean {
  const moved = Math.abs(sizeB - sizeA);
  return moved > LARGE_CHANGE_BYTES || moved > sizeA * LARGE_CHANGE_RATIO;
}

/** Files added, removed, or changed a lot (same path, different hash, large size change). */
export function fileDelta(a: PackageProfile, b: PackageProfile): PackageDiff["fileDelta"] {
  const filesA = new Map(a.files.map((f) => [f.path, f]));
  const pathsB = b.files.map((f) => f.path);
  const changedLarge = b.files
    .filter((f) => {
      const old = filesA.get(f.path);
      return old !== undefined && old.sha256 !== f.sha256 && isLargeChange(old.size, f.size);
    })
    .map((f) => f.path);
  return { added: minus(pathsB, filesA.keys()), removed: minus(filesA.keys(), pathsB), changedLarge: changedLarge.toSorted(byCodeUnit) };
}

/** Endpoints in B and not in A. */
export function endpointDelta(a: PackageProfile, b: PackageProfile): PackageDiff["endpointDelta"] {
  return { added: minus(b.endpoints, a.endpoints) };
}

/** Literal env keys read in B and not in A. */
export function envKeyDelta(a: PackageProfile, b: PackageProfile): PackageDiff["envKeyDelta"] {
  return { added: minus(b.envKeys, a.envKeys) };
}

/** `_npmUser.name`, when it is a non-empty string. */
export function publisherName(meta: VersionMeta): string | null {
  const name: unknown = (meta._npmUser as { name?: unknown } | undefined)?.name;
  return typeof name === "string" && name !== "" ? name : null;
}

/** Set when both versions name a publisher and the names differ. */
export function publisherDelta(metaA: VersionMeta, metaB: VersionMeta): PackageDiff["publisherDelta"] {
  const from = publisherName(metaA);
  const to = publisherName(metaB);
  return from !== null && to !== null && from !== to ? { from, to } : undefined;
}

/** `dropped` or `added` when attestations disappear or appear between A and B. */
export function provenanceDelta(metaA: VersionMeta, metaB: VersionMeta): PackageDiff["provenanceDelta"] {
  const a = hasAttestations(metaA);
  const b = hasAttestations(metaB);
  return a === b ? undefined : a ? "dropped" : "added";
}
