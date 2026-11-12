// Synthetic profiles and metadata for unit tests. Every field defaults to "empty".

import { CAPABILITIES, SIGNAL_SEVERITY, type Capability, type PackageProfile, type Signal, type SignalId } from "@depward/analyzer";
import type { Packument, VersionMeta } from "@depward/core";

export interface ProfileSpec {
  version?: string;
  caps?: Partial<Record<Capability, string[]>>;
  signals?: { id: SignalId; file?: string; detail?: string }[];
  scripts?: PackageProfile["scripts"];
  files?: { path: string; size?: number; sha256?: string }[];
  endpoints?: string[];
  envKeys?: string[];
}

export const NAME = "fx-pkg";

export function profile(spec: ProfileSpec = {}): PackageProfile {
  const capabilities = Object.fromEntries(CAPABILITIES.map((c) => [c, (spec.caps?.[c] ?? []).map((file, i) => ({ file, line: i + 1, evidence: `use of ${c}` }))])) as PackageProfile["capabilities"];
  const signals: Signal[] = (spec.signals ?? []).map((s) => ({
    id: s.id,
    severity: SIGNAL_SEVERITY[s.id],
    message: s.id,
    evidence: [{ file: s.file ?? "index.js", line: 1, ...(s.detail === undefined ? {} : { detail: s.detail }) }],
  }));
  return {
    name: NAME,
    version: spec.version ?? "1.0.0",
    scripts: spec.scripts ?? {},
    capabilities,
    signals,
    files: (spec.files ?? []).map((f) => ({ path: f.path, size: f.size ?? 100, kind: "js", sha256: f.sha256 ?? "0".repeat(64) })),
    endpoints: spec.endpoints ?? [],
    envKeys: spec.envKeys ?? [],
    stats: { jsFiles: 0, parsed: 0, unparsed: 0, skipped: 0, bytes: 0 },
  };
}

export function meta(version: string, extra: Partial<VersionMeta> = {}): VersionMeta {
  return {
    name: NAME,
    version,
    dist: { tarball: `https://registry.example.invalid/${NAME}/-/${NAME}-${version}.tgz` },
    _npmUser: { name: "alice" },
    ...extra,
  };
}

export const ATTESTED = {
  url: `https://registry.example.invalid/-/npm/v1/attestations/${NAME}`,
  provenance: { predicateType: "https://slsa.dev/provenance/v1" },
};

/** Metadata for a version that has a provenance attestation. */
export function attested(version: string): VersionMeta {
  return meta(version, { dist: { tarball: "https://registry.example.invalid/t.tgz", attestations: ATTESTED } });
}

/** A packument whose versions are published by `by`, with the given maintainers. */
export function packument(versions: { v: string; at: string; by: string; maintainers: string[] }[]): Packument {
  return {
    name: NAME,
    "dist-tags": {},
    versions: Object.fromEntries(versions.map((x) => [x.v, meta(x.v, { _npmUser: { name: x.by }, maintainers: x.maintainers.map((name) => ({ name })) })])),
    time: Object.fromEntries(versions.map((x) => [x.v, x.at])),
  };
}
