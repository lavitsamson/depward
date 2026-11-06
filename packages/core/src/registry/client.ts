// npm registry client. Endpoints:
// - Packument / version metadata: https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
// - Download counts: https://github.com/npm/registry/blob/main/docs/download-counts.md
//
// Version metadata and attestation presence come from the cached full packument, so
// one request answers every metadata question about a package.

import { createDiskCache, type Cache, type CacheEntry } from "../cache.ts";
import { DepwardError } from "../errors.ts";
import { verifyIntegrity, strongestHash } from "../integrity.ts";
import { Secret } from "../secret.ts";
import { httpGet, parseJson } from "./http.ts";
import { authHeaderFor, loadNpmConfig, nerfDart, normalizeRegistry, registryFor, type NpmConfig } from "./npmrc.ts";
import {
  assertPackageName,
  attestationsOf,
  packumentPath,
  pickVersion,
  toPackument,
  type Attestations,
  type Packument,
  type VersionMeta,
} from "./types.ts";

/** Read-only access to registry data. All methods treat a 404 as `null`. */
export interface RegistryClient {
  /** The full packument, or `null` if the package does not exist. */
  packument(name: string): Promise<Packument | null>;
  /** Metadata for a version or dist-tag (such as `latest`), or `null`. */
  versionMeta(name: string, version: string): Promise<VersionMeta | null>;
  /** Downloads in the last week. `null` for unknown packages and non-public registries. */
  weeklyDownloads(name: string): Promise<number | null>;
  /** Whether the version has attestations. `null` if it has none or does not exist. */
  attestations(name: string, version: string): Promise<Attestations | null>;
  /** The tarball bytes, verified against `dist.integrity` before they are returned. */
  tarball(meta: VersionMeta): Promise<Uint8Array>;
}

/** Cache lifetimes in milliseconds. */
export interface RegistryTtls {
  /** Default 10 minutes; stale entries are revalidated with `If-None-Match`. */
  packument?: number;
  /** Default 24 hours. */
  downloads?: number;
}

/** Response size caps in bytes. */
export interface RegistryLimits {
  /** Default 128 MB. Full packuments of large packages exceed 10 MB. */
  packumentBytes?: number;
  /** Default 50 MB (compressed). */
  tarballBytes?: number;
}

/** Options for {@link createRegistryClient}. */
export interface RegistryClientOptions {
  /** Default registry. Default: from `.npmrc`, else https://registry.npmjs.org/. */
  registry?: string;
  /** Token for the default registry. Default: from `.npmrc`. Never logged. */
  token?: string;
  /** Default: a disk cache in {@link defaultCacheDir}. `null` disables caching. */
  cache?: Cache | null;
  /** Per-request timeout, covering headers and body. Default 8000 ms. */
  timeoutMs?: number;
  /** Injectable for tests. Default: global `fetch`. */
  fetch?: typeof fetch;
  /** Use this config instead of reading `.npmrc` files. */
  npmConfig?: NpmConfig;
  /** Where to look for a project `.npmrc`. Default: `process.cwd()`. */
  cwd?: string;
  /** Environment used for `.npmrc` expansion. Default: `process.env`. */
  env?: Record<string, string | undefined>;
  ttl?: RegistryTtls;
  limits?: RegistryLimits;
  /** Base URL of the downloads API. Default: https://api.npmjs.org/. */
  downloadsApi?: string;
  /** Clock, for tests. */
  now?: () => number;
}

const MINUTE = 60_000;
const USER_AGENT = "depward (+https://github.com/lavitsamson/depward)";
const PUBLIC_REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.npmjs.com"]);
const MEMO_MAX = 100;

/** Creates a {@link RegistryClient}. Configuration is resolved lazily on first use. */
export function createRegistryClient(opts: RegistryClientOptions = {}): RegistryClient {
  const doFetch = opts.fetch ?? globalThis.fetch;
  const cache = opts.cache === undefined ? createDiskCache() : opts.cache;
  const timeoutMs = opts.timeoutMs ?? 8000;
  const now = opts.now ?? Date.now;
  const ttlPackument = opts.ttl?.packument ?? 10 * MINUTE;
  const ttlDownloads = opts.ttl?.downloads ?? 24 * 60 * MINUTE;
  const packumentBytes = opts.limits?.packumentBytes ?? 128 * 1024 * 1024;
  const tarballBytes = opts.limits?.tarballBytes ?? 50 * 1024 * 1024;
  const downloadsApi = normalizeRegistry(opts.downloadsApi ?? "https://api.npmjs.org/");

  let configPromise: Promise<NpmConfig> | undefined;
  const config = (): Promise<NpmConfig> => (configPromise ??= resolveConfig(opts));

  // Parsed packuments, so packument() + versionMeta() + attestations() parse once.
  const memo = new Map<string, { at: number; value: Promise<Packument | null> }>();

  async function cacheGet(ns: string, key: string): Promise<CacheEntry | null> {
    try {
      return (await cache?.get(ns, key)) ?? null;
    } catch {
      return null;
    }
  }
  async function cacheSet(ns: string, key: string, entry: CacheEntry): Promise<void> {
    try {
      await cache?.set(ns, key, entry);
    } catch {
      // A cache that can't be written (read-only disk, full disk) must not fail a check.
    }
  }

  /** GET JSON with TTL and ETag revalidation. Returns `null` on 404. */
  async function cachedGet(
    ns: string, key: string, url: string, ttl: number, maxBytes: number, cfg: NpmConfig | null,
  ): Promise<Uint8Array | null> {
    const cached = await cacheGet(ns, key);
    if (cached && now() - cached.storedAt < ttl) return cached.body;

    const headers: Record<string, string> = { accept: "application/json", "user-agent": USER_AGENT };
    if (cached?.etag) headers["if-none-match"] = cached.etag;
    const res = await httpGet(url, {
      fetch: doFetch, headers, timeoutMs, maxBytes,
      ...(cfg ? { authFor: (u: string) => authHeaderFor(cfg, u) } : {}),
    });
    if (res.status === 304 && cached) {
      await cacheSet(ns, key, { ...cached, storedAt: now() });
      return cached.body;
    }
    if (res.status === 404) return null;
    if (res.status !== 200) throw new DepwardError("NETWORK", `registry responded with HTTP ${res.status} for ${ns} ${key}`);
    const entry: CacheEntry = { body: res.body, storedAt: now() };
    const etag = res.headers.get("etag");
    if (etag) entry.etag = etag;
    await cacheSet(ns, key, entry);
    return res.body;
  }

  async function loadPackument(name: string): Promise<Packument | null> {
    const cfg = await config();
    const registry = registryFor(cfg, name);
    const body = await cachedGet("packument", `${registry} ${name}`, registry + packumentPath(name), ttlPackument, packumentBytes, cfg);
    return body === null ? null : toPackument(parseJson(body, `packument for ${name}`), name);
  }

  function packument(name: string): Promise<Packument | null> {
    try {
      assertPackageName(name);
    } catch (err) {
      return Promise.reject(err);
    }
    const hit = memo.get(name);
    if (hit && now() - hit.at < ttlPackument) return hit.value;
    const value = loadPackument(name);
    memo.delete(name);
    memo.set(name, { at: now(), value });
    if (memo.size > MEMO_MAX) memo.delete(memo.keys().next().value as string);
    // Don't remember failures or 404s: a missing name can be registered at any moment.
    const forget = (): void => {
      if (memo.get(name)?.value === value) memo.delete(name);
    };
    value.then((doc) => doc === null && forget(), forget);
    return value;
  }

  return {
    packument,

    async versionMeta(name, version) {
      const doc = await packument(name);
      return doc ? pickVersion(doc, version) : null;
    },

    async attestations(name, version) {
      const doc = await packument(name);
      const meta = doc ? pickVersion(doc, version) : null;
      return meta ? attestationsOf(meta, registryFor(await config(), name)) : null;
    },

    async weeklyDownloads(name) {
      assertPackageName(name);
      const registry = registryFor(await config(), name);
      if (!PUBLIC_REGISTRY_HOSTS.has(new URL(registry).hostname)) return null;
      // Scoped names are accepted unencoded by the point endpoint.
      const url = `${downloadsApi}downloads/point/last-week/${name}`;
      const body = await cachedGet("downloads", name, url, ttlDownloads, 64 * 1024, null);
      if (body === null) return null;
      const doc = parseJson(body, `download counts for ${name}`) as { downloads?: unknown };
      return typeof doc.downloads === "number" && Number.isFinite(doc.downloads) ? doc.downloads : null;
    },

    async tarball(meta) {
      const cfg = await config();
      const { dist } = meta;
      const sri = dist.integrity ? strongestHash(dist.integrity) : null;
      const key = sri ? `${sri.algorithm}-${sri.digest}` : null;
      if (key) {
        const cached = await cacheGet("tarball", key);
        if (cached) {
          try {
            verifyIntegrity(cached.body, dist);
            return cached.body;
          } catch {
            // Corrupt or tampered cache entry: fetch again.
          }
        }
      }
      const res = await httpGet(dist.tarball, {
        fetch: doFetch, headers: { "user-agent": USER_AGENT }, timeoutMs, maxBytes: tarballBytes,
        authFor: (u) => authHeaderFor(cfg, u),
      });
      if (res.status !== 200) {
        throw new DepwardError("NETWORK", `tarball download for ${meta.name}@${meta.version} returned HTTP ${res.status}`);
      }
      verifyIntegrity(res.body, dist);
      if (key) await cacheSet("tarball", key, { body: res.body, storedAt: now() });
      return res.body;
    },
  };
}

async function resolveConfig(opts: RegistryClientOptions): Promise<NpmConfig> {
  const base = opts.npmConfig ?? (await loadNpmConfig({
    ...(opts.cwd === undefined ? {} : { cwd: opts.cwd }),
    ...(opts.env === undefined ? {} : { env: opts.env }),
  }));
  const cfg: NpmConfig = { registry: base.registry, scopes: { ...base.scopes }, auth: [...base.auth] };
  if (opts.registry !== undefined) {
    try {
      cfg.registry = normalizeRegistry(opts.registry);
    } catch (cause) {
      throw new DepwardError("INVALID_ARGUMENT", "invalid registry URL", { cause });
    }
  }
  if (opts.token !== undefined) {
    const prefix = nerfDart(cfg.registry);
    cfg.auth = [...cfg.auth.filter((a) => a.prefix !== prefix), { prefix, token: new Secret(opts.token) }];
  }
  return cfg;
}
