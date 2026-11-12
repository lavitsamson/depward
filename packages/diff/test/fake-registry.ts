// An offline registry built from inline package definitions: packuments, tarballs (packed
// in memory with real integrity hashes), and download counts. Every package is synthetic
// and inert; endpoints use example.invalid only.

import { createHash } from "node:crypto";
import { createMemoryCache, createRegistryClient, NPM_REGISTRY, type Packument, type RegistryClient, type VersionMeta } from "@depward/core";
import { packTarball } from "@depward/core/testing";

export interface FakeVersion {
  /** Package files other than package.json. */
  files?: Record<string, string>;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  /** ISO publish time. Default 2026-01-01. */
  time?: string;
  /** `_npmUser.name`. Default `alice`. */
  by?: string;
}

export interface FakePackage {
  versions: Record<string, FakeVersion>;
  /** Weekly downloads. Default 1,000,000. */
  downloads?: number;
}

export interface FakeRegistry {
  client: RegistryClient;
  /** URLs requested, in order. */
  requests: string[];
  /** The SRI integrity the registry publishes for a version. */
  integrity: (name: string, version: string) => string;
}

const sri = (bytes: Uint8Array): string => `sha512-${createHash("sha512").update(bytes).digest("base64")}`;

export function fakeRegistry(packages: Record<string, FakePackage>): FakeRegistry {
  const packuments = new Map<string, Packument>();
  const tarballs = new Map<string, Uint8Array>();
  for (const [name, pkg] of Object.entries(packages)) {
    const versions: Record<string, VersionMeta> = {};
    const time: Record<string, string> = {};
    for (const [version, v] of Object.entries(pkg.versions)) {
      const manifest = { name, version, ...(v.scripts ? { scripts: v.scripts } : {}), ...(v.dependencies ? { dependencies: v.dependencies } : {}) };
      const bytes = packTarball([
        { path: "package.json", data: JSON.stringify(manifest) },
        ...Object.entries(v.files ?? { "index.js": "module.exports = 1;\n" }).map(([path, data]) => ({ path, data })),
      ]);
      const file = `${name.replace(/^@[^/]+\//, "")}-${version}.tgz`;
      tarballs.set(file, bytes);
      versions[version] = {
        ...manifest,
        dist: { tarball: `${NPM_REGISTRY}${name}/-/${file}`, integrity: sri(bytes) },
        _npmUser: { name: v.by ?? "alice" },
        maintainers: [{ name: "alice" }],
      };
      time[version] = v.time ?? "2026-01-01T00:00:00.000Z";
    }
    const times = Object.values(time).toSorted();
    const latest = Object.keys(versions).at(-1) ?? "";
    packuments.set(name, { name, "dist-tags": { latest }, versions, time: { created: times[0] ?? "", modified: times.at(-1) ?? "", ...time } });
  }

  const requests: string[] = [];
  const fetchImpl = async (input: string | URL | Request): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input);
    requests.push(url.href);
    const path = decodeURIComponent(url.pathname);
    if (url.hostname === "api.npmjs.org") {
      const name = path.replace(/^\/downloads\/point\/last-week\//, "");
      const pkg = packages[name];
      return pkg ? Response.json({ downloads: pkg.downloads ?? 1_000_000, package: name }) : new Response("{}", { status: 404 });
    }
    const tgz = /\/-\/([^/]+\.tgz)$/.exec(path)?.[1];
    if (tgz) {
      const bytes = tarballs.get(tgz);
      return bytes ? new Response(new Uint8Array(bytes)) : new Response("not found", { status: 404 });
    }
    const doc = packuments.get(path.slice(1));
    return doc ? Response.json(doc) : Response.json({ error: "Not found" }, { status: 404 });
  };

  const client = createRegistryClient({
    cache: createMemoryCache(),
    npmConfig: { registry: NPM_REGISTRY, scopes: {}, auth: [] },
    fetch: fetchImpl as typeof fetch,
  });
  return {
    client,
    requests,
    integrity: (name, version) => packuments.get(name)?.versions[version]?.dist.integrity ?? "",
  };
}
