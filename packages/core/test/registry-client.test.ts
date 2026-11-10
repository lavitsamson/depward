import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { createFixtureFetch, createFixtureRegistryClient } from "../src/testing.ts";
import {
  createMemoryCache,
  createRegistryClient,
  isDepwardError,
  npmConfigFrom,
  type VersionMeta,
} from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const MIN = 60_000;

function clock(start = 1_700_000_000_000): { now: () => number; advance: (ms: number) => void } {
  let t = start;
  return { now: () => t, advance: (ms) => void (t += ms) };
}

describe("packument and versionMeta", () => {
  test("fetches the full packument once and answers metadata questions from it", async () => {
    const client = createFixtureRegistryClient(FIXTURES);
    const doc = await client.packument("depward-fixture-stable");
    expect(doc?.time["2.0.0"]).toBe("2024-06-01T10:00:00.000Z");
    expect(doc?.maintainers?.[0]?.name).toBe("fixture-maintainer");
    expect(Object.keys(doc?.versions ?? {})).toEqual(["1.0.0", "1.1.0", "2.0.0"]);

    expect((await client.versionMeta("depward-fixture-stable", "1.0.0"))?.deprecated).toBe("Use 2.x");
    expect((await client.versionMeta("depward-fixture-stable", "latest"))?.version).toBe("2.0.0");
    expect((await client.versionMeta("depward-fixture-stable", "legacy"))?.version).toBe("1.1.0");
    expect((await client.versionMeta("depward-fixture-stable", "2.0.0"))?._npmUser?.name).toBe("fixture-maintainer");
    expect(await client.versionMeta("depward-fixture-stable", "9.9.9")).toBeNull();

    expect(client.requests.map((r) => r.url)).toEqual(["https://registry.npmjs.org/depward-fixture-stable"]);
    // Full document: no abbreviated Accept header.
    expect(client.requests[0]?.headers["accept"]).toBe("application/json");
  });

  test("prototype keys are never treated as versions or tags", async () => {
    const client = createFixtureRegistryClient(FIXTURES);
    for (const key of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      expect(await client.versionMeta("depward-fixture-stable", key)).toBeNull();
    }
  });

  test("encodes scoped names as @scope%2fname", async () => {
    const client = createFixtureRegistryClient(FIXTURES);
    expect((await client.packument("@depward-fixture/scoped"))?.["dist-tags"]["latest"]).toBe("0.1.0");
    expect(client.requests[0]?.url).toBe("https://registry.npmjs.org/@depward-fixture%2fscoped");
  });

  test("returns null for unknown packages and does not cache the 404", async () => {
    const c = clock();
    const client = createFixtureRegistryClient(FIXTURES, { now: c.now });
    expect(await client.packument("depward-fixture-does-not-exist")).toBeNull();
    c.advance(1);
    expect(await client.packument("depward-fixture-does-not-exist")).toBeNull();
    expect(client.requests).toHaveLength(2);
  });

  test("rejects names that are not npm package names before any request", async () => {
    const client = createFixtureRegistryClient(FIXTURES);
    for (const bad of ["", "..", "../-/whoami", "a b", "@scope/..", "a/b/c", "x?y", "@/x"]) {
      await expect(client.packument(bad), bad).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_ARGUMENT"));
    }
    expect(client.requests).toHaveLength(0);
  });

  test("rejects documents that are not the requested packument", async () => {
    const fetch = (async () => new Response(JSON.stringify({ name: "other", versions: {} }))) as unknown as typeof globalThis.fetch;
    const client = createRegistryClient({ fetch, cache: null, npmConfig: npmConfigFrom() });
    await expect(client.packument("depward-fixture-stable")).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_RESPONSE"));
    const garbage = (async () => new Response("<html>")) as unknown as typeof globalThis.fetch;
    const client2 = createRegistryClient({ fetch: garbage, cache: null, npmConfig: npmConfigFrom() });
    await expect(client2.packument("x")).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_RESPONSE"));
  });

  test("surfaces unexpected HTTP statuses as NETWORK errors", async () => {
    const fetch = (async () => new Response("busy", { status: 503 })) as unknown as typeof globalThis.fetch;
    const client = createRegistryClient({ fetch, cache: null, npmConfig: npmConfigFrom() });
    await expect(client.packument("x")).rejects.toSatisfy((e) => isDepwardError(e, "NETWORK"));
  });
});

describe("caching", () => {
  test("serves fresh entries from cache, then revalidates stale ones with If-None-Match", async () => {
    const c = clock();
    const cache = createMemoryCache();
    const fx = createFixtureFetch(FIXTURES);
    const make = () => createRegistryClient({ fetch: fx.fetch, cache, now: c.now, npmConfig: npmConfigFrom() });

    await make().packument("depward-fixture-stable");
    c.advance(5 * MIN);
    await make().packument("depward-fixture-stable"); // fresh: served from the cache
    expect(fx.requests).toHaveLength(1);

    c.advance(6 * MIN);
    const doc = await make().packument("depward-fixture-stable"); // stale: revalidated
    expect(doc?.name).toBe("depward-fixture-stable");
    expect(fx.requests).toHaveLength(2);
    expect(fx.requests[1]?.headers["if-none-match"]).toMatch(/^"[0-9a-f]{32}"$/);

    c.advance(5 * MIN);
    await make().packument("depward-fixture-stable"); // the 304 refreshed storedAt
    expect(fx.requests).toHaveLength(2);
  });

  test("TTLs are configurable per data type", async () => {
    const c = clock();
    const client = createFixtureRegistryClient(FIXTURES, { now: c.now, ttl: { packument: 0, downloads: 2 * MIN } });
    await client.packument("depward-fixture-stable");
    c.advance(1);
    await client.packument("depward-fixture-stable");
    await client.weeklyDownloads("depward-fixture-stable");
    c.advance(MIN);
    await client.weeklyDownloads("depward-fixture-stable");
    expect(client.requests.map((r) => new URL(r.url).hostname)).toEqual(["registry.npmjs.org", "registry.npmjs.org", "api.npmjs.org"]);
  });

  test("a broken cache never fails a lookup", async () => {
    const broken = {
      get: async () => {
        throw new Error("disk on fire");
      },
      set: async () => {
        throw new Error("disk on fire");
      },
    };
    const fx = createFixtureFetch(FIXTURES);
    const client = createRegistryClient({ fetch: fx.fetch, cache: broken, npmConfig: npmConfigFrom() });
    expect((await client.packument("depward-fixture-stable"))?.name).toBe("depward-fixture-stable");
  });
});

describe("offline mode", () => {
  test("serves cached data at any age, fails uncached data with OFFLINE, and never fetches", async () => {
    const c = clock();
    const cache = createMemoryCache();
    const fx = createFixtureFetch(FIXTURES);
    const online = createRegistryClient({ fetch: fx.fetch, cache, now: c.now, npmConfig: npmConfigFrom() });
    const meta = (await online.versionMeta("depward-fixture-stable", "2.0.0"))!;
    await online.weeklyDownloads("depward-fixture-stable");
    const bytes = await online.tarball(meta);
    const before = fx.requests.length;

    c.advance(30 * 24 * 60 * MIN); // far past every TTL
    const offline = createRegistryClient({ fetch: fx.fetch, cache, now: c.now, npmConfig: npmConfigFrom(), offline: true });
    expect((await offline.packument("depward-fixture-stable"))?.name).toBe("depward-fixture-stable");
    expect(await offline.weeklyDownloads("depward-fixture-stable")).toBe(1234567);
    expect(await offline.tarball(meta)).toEqual(bytes);

    const err = await offline.packument("depward-fixture-fresh").catch((e: unknown) => e);
    expect(isDepwardError(err, "OFFLINE")).toBe(true);
    const tgz = await offline.tarball({ ...meta, version: "9.9.9", dist: { ...meta.dist, integrity: `sha512-${"B".repeat(86)}==` } }).catch((e: unknown) => e);
    expect(isDepwardError(tgz, "OFFLINE")).toBe(true);
    expect(fx.requests).toHaveLength(before);
  });

  test("DEPWARD_OFFLINE=1 turns it on by default; an explicit option wins", async () => {
    const fx = createFixtureFetch(FIXTURES);
    const env = { DEPWARD_OFFLINE: "1" };
    const byEnv = createRegistryClient({ fetch: fx.fetch, cache: createMemoryCache(), npmConfig: npmConfigFrom(), env });
    expect(isDepwardError(await byEnv.packument("depward-fixture-stable").catch((e: unknown) => e), "OFFLINE")).toBe(true);
    const forced = createRegistryClient({ fetch: fx.fetch, cache: createMemoryCache(), npmConfig: npmConfigFrom(), env, offline: false });
    expect((await forced.packument("depward-fixture-stable"))?.name).toBe("depward-fixture-stable");
    const other = createRegistryClient({ fetch: fx.fetch, cache: createMemoryCache(), npmConfig: npmConfigFrom(), env: { DEPWARD_OFFLINE: "0" } });
    expect((await other.packument("depward-fixture-stable"))?.name).toBe("depward-fixture-stable");
    expect(fx.requests).toHaveLength(2);
  });
});

describe("weeklyDownloads", () => {
  test("reads the point endpoint, with scoped names unencoded", async () => {
    const client = createFixtureRegistryClient(FIXTURES);
    expect(await client.weeklyDownloads("depward-fixture-stable")).toBe(1234567);
    expect(await client.weeklyDownloads("@depward-fixture/scoped")).toBe(12);
    expect(await client.weeklyDownloads("depward-fixture-does-not-exist")).toBeNull();
    expect(client.requests[1]?.url).toBe("https://api.npmjs.org/downloads/point/last-week/@depward-fixture/scoped");
  });

  test("returns null without a request for packages served by a non-public registry", async () => {
    const npmConfig = npmConfigFrom(new Map([["@corp:registry", "https://corp.example.com/"]]));
    const client = createFixtureRegistryClient(FIXTURES, { npmConfig });
    expect(await client.weeklyDownloads("@corp/thing")).toBeNull();
    const priv = createFixtureRegistryClient(FIXTURES, { registry: "https://npm.example.com/" });
    expect(await priv.weeklyDownloads("depward-fixture-stable")).toBeNull();
    expect([...client.requests, ...priv.requests]).toHaveLength(0);
  });
});

describe("attestations", () => {
  test("reports presence and predicate type from dist.attestations", async () => {
    const client = createFixtureRegistryClient(FIXTURES);
    expect(await client.attestations("depward-fixture-stable", "2.0.0")).toEqual({
      url: "https://registry.npmjs.org/-/npm/v1/attestations/depward-fixture-stable@2.0.0",
      provenancePredicateType: "https://slsa.dev/provenance/v1",
    });
    expect(await client.attestations("depward-fixture-stable", "1.1.0")).toBeNull();
    expect(await client.attestations("@depward-fixture/scoped", "latest")).toBeNull();
    expect(await client.attestations("depward-fixture-does-not-exist", "1.0.0")).toBeNull();
  });
});

describe("tarball", () => {
  test("downloads and verifies the tarball, then serves it from the integrity-keyed cache", async () => {
    const cache = createMemoryCache();
    const fx = createFixtureFetch(FIXTURES);
    const client = createRegistryClient({ fetch: fx.fetch, cache, npmConfig: npmConfigFrom() });
    const meta = await client.versionMeta("depward-fixture-stable", "2.0.0");
    const bytes = await client.tarball(meta!);
    expect([bytes[0], bytes[1]]).toEqual([0x1f, 0x8b]); // gzip magic
    const again = await createRegistryClient({ fetch: fx.fetch, cache, npmConfig: npmConfigFrom() }).tarball(meta!);
    expect(again).toEqual(bytes);
    expect(fx.requests.filter((r) => r.url.endsWith(".tgz"))).toHaveLength(1);
  });

  test("throws INTEGRITY_MISMATCH and caches nothing when the bytes don't match", async () => {
    const cache = createMemoryCache();
    const client = createFixtureRegistryClient(FIXTURES, { cache });
    const meta = (await client.versionMeta("depward-fixture-stable", "2.0.0"))!;
    const tampered: VersionMeta = { ...meta, dist: { ...meta.dist, integrity: `sha512-${"A".repeat(86)}==` } };
    await expect(client.tarball(tampered)).rejects.toSatisfy((e) => isDepwardError(e, "INTEGRITY_MISMATCH"));
    expect(await cache.get("tarball", `sha512-${"A".repeat(86)}==`)).toBeNull();
  });

  test("ignores a tampered cache entry and re-downloads", async () => {
    const cache = createMemoryCache();
    const client = createFixtureRegistryClient(FIXTURES, { cache });
    const meta = (await client.versionMeta("depward-fixture-stable", "2.0.0"))!;
    await cache.set("tarball", meta.dist.integrity!, { body: new Uint8Array([1, 2, 3]), storedAt: 0 });
    expect((await client.tarball(meta)).byteLength).toBe(232);
  });

  test("sends credentials to the registry host only, never to a foreign tarball host", async () => {
    const npmConfig = npmConfigFrom(new Map([["//registry.npmjs.org/:_authToken", "npm_s3cr3t"]]));
    const client = createFixtureRegistryClient(FIXTURES, { npmConfig, cache: null });
    const meta = (await client.versionMeta("depward-fixture-stable", "2.0.0"))!;
    await client.tarball(meta);
    const foreign: VersionMeta = {
      ...meta,
      dist: { ...meta.dist, tarball: "https://evil.example.invalid/-/depward-fixture-stable-2.0.0.tgz" },
    };
    await client.tarball(foreign);
    const auth = client.requests.map((r) => [new URL(r.url).hostname, r.headers["authorization"]]);
    expect(auth).toEqual([
      ["registry.npmjs.org", "Bearer npm_s3cr3t"],
      ["registry.npmjs.org", "Bearer npm_s3cr3t"],
      ["evil.example.invalid", undefined],
    ]);
  });

  test("an explicit token applies to the configured registry", async () => {
    const client = createFixtureRegistryClient(FIXTURES, { token: "opt-token" });
    await client.packument("depward-fixture-stable");
    expect(client.requests[0]?.headers["authorization"]).toBe("Bearer opt-token");
  });
});
