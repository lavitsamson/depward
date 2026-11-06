// Registry document shapes. References:
// https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
// https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md
// `dist.attestations` is not in npm's docs; its shape follows npm's pacote client
// (`{ url, provenance: { predicateType } }`).
//
// Every field comes from an untrusted registry. Only the minimum structure is
// checked here; consumers must still treat strings as hostile.

import { DepwardError } from "../errors.ts";

/** A person entry such as `_npmUser` or a `maintainers` item. */
export interface Person {
  name?: string;
  email?: string;
}

/** `dist.attestations` as published by the registry. */
export interface DistAttestations {
  url: string;
  provenance?: { predicateType: string };
}

/** The `dist` object of a version. */
export interface Dist {
  tarball: string;
  integrity?: string;
  shasum?: string;
  fileCount?: number;
  unpackedSize?: number;
  attestations?: DistAttestations;
  signatures?: { keyid: string; sig: string }[];
}

/** Metadata for one published version (one entry of `packument.versions`). */
export interface VersionMeta {
  name: string;
  version: string;
  dist: Dist;
  deprecated?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  _npmUser?: Person;
  maintainers?: Person[];
  [key: string]: unknown;
}

/** The full packument (`GET {registry}/{name}` with no abbreviated Accept header). */
export interface Packument {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, VersionMeta>;
  /** Publish time per version, plus `created` and `modified`. */
  time: Record<string, string>;
  maintainers?: Person[];
  [key: string]: unknown;
}

/** Attestation presence for a version. v0.x does not verify them cryptographically. */
export interface Attestations {
  /** Absolute URL of the attestation bundle. */
  url: string;
  /** SLSA provenance predicate type, when the registry reports one. */
  provenancePredicateType: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Keeps only string values of a record, so lookups never hit odd types. */
function stringRecord(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isRecord(value)) return out;
  for (const [k, v] of Object.entries(value)) if (typeof v === "string") out[k] = v;
  return out;
}

/**
 * Validates the minimum structure of a packument. Versions without a string
 * `dist.tarball` are dropped. Throws `INVALID_RESPONSE` when the document is not a
 * packument at all.
 */
export function toPackument(doc: unknown, expectedName: string): Packument {
  if (!isRecord(doc) || !isRecord(doc["versions"])) {
    throw new DepwardError("INVALID_RESPONSE", `registry document for ${expectedName} is not a packument`);
  }
  if (doc["name"] !== expectedName) {
    throw new DepwardError("INVALID_RESPONSE", `registry returned a packument for a different package than ${expectedName}`);
  }
  const versions: Record<string, VersionMeta> = {};
  for (const [v, meta] of Object.entries(doc["versions"])) {
    if (isRecord(meta) && isRecord(meta["dist"]) && typeof meta["dist"]["tarball"] === "string") {
      versions[v] = { ...meta, name: expectedName, version: v } as VersionMeta;
    }
  }
  return {
    ...doc,
    name: expectedName,
    "dist-tags": stringRecord(doc["dist-tags"]),
    versions,
    time: stringRecord(doc["time"]),
  };
}

/** Looks up a version or dist-tag in a packument using own properties only. */
export function pickVersion(packument: Packument, versionOrTag: string): VersionMeta | null {
  const { versions } = packument;
  if (Object.hasOwn(versions, versionOrTag)) return versions[versionOrTag] ?? null;
  const tags = packument["dist-tags"];
  if (Object.hasOwn(tags, versionOrTag)) {
    const target = tags[versionOrTag];
    if (target !== undefined && Object.hasOwn(versions, target)) return versions[target] ?? null;
  }
  return null;
}

/** Reads `dist.attestations`, resolving its URL against the registry. */
export function attestationsOf(meta: VersionMeta, registry: string): Attestations | null {
  const raw: unknown = meta.dist.attestations;
  if (!isRecord(raw) || typeof raw["url"] !== "string") return null;
  let url: string;
  try {
    url = new URL(raw["url"], registry).href;
  } catch {
    return null;
  }
  const prov = raw["provenance"];
  const predicateType = isRecord(prov) && typeof prov["predicateType"] === "string" ? prov["predicateType"] : null;
  return { url, provenancePredicateType: predicateType };
}

const NAME_RE = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9_.~-][\w.~-]*$/i;

/**
 * Throws `INVALID_ARGUMENT` unless `name` looks like an npm package name. This keeps
 * names such as `../-/whoami` out of registry URLs. Legacy upper-case names are allowed.
 */
export function assertPackageName(name: string): void {
  const base = name.slice(name.indexOf("/") + 1);
  if (name.length > 214 || !NAME_RE.test(name) || base === "." || base === "..") {
    throw new DepwardError("INVALID_ARGUMENT", "invalid package name");
  }
}

/** The packument path segment: `@scope%2fname` for scoped names. */
export function packumentPath(name: string): string {
  return name.startsWith("@") ? name.replace("/", "%2f") : name;
}
