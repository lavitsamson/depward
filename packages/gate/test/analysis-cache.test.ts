// The analysis-results cache of checkTarball (ADR 0005). Offline; package code is never
// executed.

import { fileURLToPath } from "node:url";
import * as analyzer from "@depward/analyzer";
import { DepwardError, createMemoryCache, type Cache, type RegistryClient, type VersionMeta } from "@depward/core";
import { createFixtureRegistryClient, packTarball } from "@depward/core/testing";
import { describe, expect, test } from "vitest";
import { checkTarball } from "../src/index.ts";
import { analysisCacheKey } from "../src/tarball/cache.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const keyOf = (meta: VersionMeta, opts: Parameters<typeof analysisCacheKey>[1]): string | null => analysisCacheKey(meta, opts, analyzer);

/** The fixture registry, counting tarball() calls; `bytes` overrides what it serves. */
function counting(bytes?: () => Uint8Array | Promise<Uint8Array>): RegistryClient & { calls: number } {
  const base = createFixtureRegistryClient(FIXTURES);
  const client = {
    ...base,
    calls: 0,
    tarball(meta: VersionMeta) {
      client.calls++;
      return bytes ? Promise.resolve(bytes()) : base.tarball(meta);
    },
  };
  return client;
}

async function metaOf(name: string, version: string): Promise<VersionMeta> {
  const meta = await createFixtureRegistryClient(FIXTURES).versionMeta(name, version);
  if (!meta) throw new Error(`fixture ${name}@${version} missing`);
  return meta;
}

describe("analysis cache", () => {
  test("a hit skips the download and gives the same result", async () => {
    const meta = await metaOf("depward-fixture-takeover", "1.1.0");
    const analysisCache = createMemoryCache();
    const registry = counting();
    const first = await checkTarball(meta, { registry, analysisCache });
    const second = await checkTarball(meta, { registry, analysisCache });
    expect(registry.calls).toBe(1);
    expect(second).toEqual(first);
    expect(second.findings.map((f) => f.id)).toContain("env-exfil-pattern");
  });

  test("the key covers the integrity, the analyzer revision, and the limits", async () => {
    const meta = await metaOf("depward-fixture-stable", "2.0.0");
    const key = keyOf(meta, {});
    expect(key).toMatch(/^analyzer@[^:]+:r\d+:sha512-/);
    expect(keyOf(meta, { analyze: { maxFileBytes: 10 } })).not.toBe(key);
    expect(keyOf(meta, { tarLimits: { maxEntries: 5 } })).not.toBe(key);
    expect(keyOf({ ...meta, dist: { ...meta.dist, integrity: "sha512-Zm9v" } }, {})).not.toBe(key);
  });

  test("different limits are a miss", async () => {
    const meta = await metaOf("depward-fixture-stable", "2.0.0");
    const analysisCache = createMemoryCache();
    const registry = counting();
    await checkTarball(meta, { registry, analysisCache });
    await checkTarball(meta, { registry, analysisCache, analyze: { maxFileBytes: 1024 } });
    expect(registry.calls).toBe(2);
  });

  test("a version without an integrity hash is never cached", async () => {
    const meta = await metaOf("depward-fixture-stable", "2.0.0");
    const { integrity: _integrity, ...dist } = meta.dist;
    const legacy = { ...meta, dist };
    expect(keyOf(legacy, {})).toBeNull();
    const analysisCache = createMemoryCache();
    const bytes = packTarball([{ path: "package.json", data: '{ "name": "x", "version": "1.0.0" }' }]);
    const registry = counting(() => bytes);
    await checkTarball(legacy, { registry, analysisCache });
    await checkTarball(legacy, { registry, analysisCache });
    expect(registry.calls).toBe(2);
  });

  test("failures are not cached", async () => {
    const meta = await metaOf("depward-fixture-stable", "2.0.0");
    const analysisCache = createMemoryCache();
    let fail = true;
    const registry = counting(() => {
      if (fail) throw new DepwardError("NETWORK", "offline for the test");
      return createFixtureRegistryClient(FIXTURES).tarball(meta);
    });
    const r1 = await checkTarball(meta, { registry, analysisCache });
    expect(r1.errors.map((e) => e.code)).toEqual(["NETWORK"]);
    fail = false;
    const r2 = await checkTarball(meta, { registry, analysisCache });
    expect(r2.errors).toEqual([]);
    expect(registry.calls).toBe(2);
  });

  test("an unsafe archive is not cached", async () => {
    const meta = await metaOf("depward-fixture-unsafe", "1.0.0");
    const analysisCache = createMemoryCache();
    const registry = counting();
    expect((await checkTarball(meta, { registry, analysisCache })).findings.map((f) => f.id)).toEqual(["tarball-unsafe"]);
    await checkTarball(meta, { registry, analysisCache });
    expect(registry.calls).toBe(2);
  });

  test("a corrupt or unreadable entry is recomputed, not trusted or thrown", async () => {
    const meta = await metaOf("depward-fixture-takeover", "1.1.0");
    const key = keyOf(meta, {})!;
    const store = createMemoryCache();
    for (const body of ["not json", '{"name":"x"}', "null"]) {
      await store.set("analysis", key, { body: new TextEncoder().encode(body), storedAt: 0 });
      const registry = counting();
      const r = await checkTarball(meta, { registry, analysisCache: store });
      expect(registry.calls).toBe(1);
      expect(r.findings.map((f) => f.id)).toContain("env-exfil-pattern");
    }
    const broken: Cache = {
      get: () => Promise.reject(new Error("disk on fire")),
      set: () => Promise.reject(new Error("disk on fire")),
    };
    const r = await checkTarball(meta, { registry: counting(), analysisCache: broken });
    expect(r.errors).toEqual([]);
    expect(r.findings.map((f) => f.id)).toContain("env-exfil-pattern");
  });
});
