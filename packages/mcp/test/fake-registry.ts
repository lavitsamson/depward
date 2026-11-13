// A tiny offline registry for diff_versions tests: packuments and tarballs packed in
// memory with real integrity hashes. Every package is synthetic and inert; endpoints use
// example.invalid only.

import { createHash } from "node:crypto";
import { createMemoryCache, createRegistryClient, NPM_REGISTRY, type Packument, type RegistryClient, type VersionMeta } from "@depward/core";
import { packTarball } from "@depward/core/testing";

export interface FakeVersion {
  /** Package files other than package.json. */
  files?: Record<string, string>;
  scripts?: Record<string, string>;
}

const sri = (bytes: Uint8Array): string => `sha512-${createHash("sha512").update(bytes).digest("base64")}`;

/** A registry client serving `packages` (name → version → contents). Unknown URLs are 404. */
export function fakeRegistry(packages: Record<string, Record<string, FakeVersion>>): RegistryClient {
  const packuments = new Map<string, Packument>();
  const tarballs = new Map<string, Uint8Array>();
  for (const [name, versions] of Object.entries(packages)) {
    const metas: Record<string, VersionMeta> = {};
    const time: Record<string, string> = {};
    for (const [version, v] of Object.entries(versions)) {
      const manifest = { name, version, ...(v.scripts ? { scripts: v.scripts } : {}) };
      const bytes = packTarball([
        { path: "package.json", data: JSON.stringify(manifest) },
        ...Object.entries(v.files ?? { "index.js": "module.exports = 1;\n" }).map(([path, data]) => ({ path, data })),
      ]);
      const file = `${name}-${version}.tgz`;
      tarballs.set(file, bytes);
      metas[version] = { ...manifest, dist: { tarball: `${NPM_REGISTRY}${name}/-/${file}`, integrity: sri(bytes) }, _npmUser: { name: "alice" }, maintainers: [{ name: "alice" }] };
      time[version] = "2026-01-01T00:00:00.000Z";
    }
    const latest = Object.keys(metas).at(-1) ?? "";
    packuments.set(name, { name, "dist-tags": { latest }, versions: metas, time: { created: "2026-01-01T00:00:00.000Z", modified: "2026-01-01T00:00:00.000Z", ...time } });
  }

  const fetchImpl = async (input: string | URL | Request): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input);
    const path = decodeURIComponent(url.pathname);
    const tgz = /\/-\/([^/]+\.tgz)$/.exec(path)?.[1];
    if (tgz) {
      const bytes = tarballs.get(tgz);
      return bytes ? new Response(new Uint8Array(bytes)) : new Response("not found", { status: 404 });
    }
    const doc = packuments.get(path.slice(1));
    return doc ? Response.json(doc) : Response.json({ error: "Not found" }, { status: 404 });
  };
  return createRegistryClient({ cache: createMemoryCache(), npmConfig: { registry: NPM_REGISTRY, scopes: {}, auth: [] }, fetch: fetchImpl as typeof fetch });
}
