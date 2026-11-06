import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { createDiskCache, createMemoryCache, defaultCacheDir, type Cache } from "../src/index.ts";

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-cache-"));
});
afterEach(async () => rm(dir, { recursive: true, force: true }));

describe.each([
  ["memory", (): Cache => createMemoryCache()],
  ["disk", (): Cache => createDiskCache(dir)],
])("%s cache", (_name, make) => {
  test("round-trips body, etag, and storedAt", async () => {
    const cache = make();
    expect(await cache.get("packument", "k")).toBeNull();
    await cache.set("packument", "k", { body: bytes('{"a":"line1\\nline2"}'), etag: 'W/"abc"', storedAt: 42 });
    expect(await cache.get("packument", "k")).toEqual({ body: bytes('{"a":"line1\\nline2"}'), etag: 'W/"abc"', storedAt: 42 });
    expect(await cache.get("downloads", "k")).toBeNull();
  });

  test("handles binary bodies containing newlines and no etag", async () => {
    const cache = make();
    const body = new Uint8Array([0x0a, 0, 255, 0x0a, 1]);
    await cache.set("tarball", "sha512-x", { body, storedAt: 1 });
    expect(await cache.get("tarball", "sha512-x")).toEqual({ body, storedAt: 1 });
  });

  test("overwrites existing entries", async () => {
    const cache = make();
    await cache.set("packument", "k", { body: bytes("old"), storedAt: 1 });
    await cache.set("packument", "k", { body: bytes("new"), storedAt: 2 });
    expect((await cache.get("packument", "k"))?.body).toEqual(bytes("new"));
  });
});

describe("disk cache", () => {
  test("treats corrupt files as misses and leaves no temp files behind", async () => {
    const cache = createDiskCache(dir);
    await cache.set("packument", "k", { body: bytes("x"), storedAt: 1 });
    const [file] = await readdir(join(dir, "packument"));
    expect(file).toMatch(/^[0-9a-f]{64}$/);
    await writeFile(join(dir, "packument", file!), "not a header");
    expect(await cache.get("packument", "k")).toBeNull();
    await writeFile(join(dir, "packument", file!), '{"v":2,"storedAt":1}\nbody');
    expect(await cache.get("packument", "k")).toBeNull();
  });

  test("survives concurrent writers to the same key", async () => {
    const a = createDiskCache(dir);
    const b = createDiskCache(dir);
    await Promise.all(
      Array.from({ length: 20 }, (_, i) => (i % 2 ? a : b).set("packument", "same", { body: bytes(`v${i}`), storedAt: i })),
    );
    const got = await a.get("packument", "same");
    expect(got?.body).toEqual(bytes(`v${got?.storedAt}`));
    expect(await readdir(join(dir, "packument"))).toHaveLength(1);
  });

  test("rejects namespaces that could escape the cache directory", async () => {
    await expect(createDiskCache(dir).set("../x", "k", { body: bytes(""), storedAt: 0 })).rejects.toThrow(TypeError);
  });
});

test("defaultCacheDir follows DEPWARD_CACHE_DIR, XDG_CACHE_HOME, then the platform", () => {
  expect(defaultCacheDir({ DEPWARD_CACHE_DIR: "/c", XDG_CACHE_HOME: "/x" }, "linux", "/h")).toBe("/c");
  expect(defaultCacheDir({ XDG_CACHE_HOME: "/x" }, "linux", "/h")).toBe(join("/x", "depward"));
  expect(defaultCacheDir({}, "linux", "/h")).toBe(join("/h", ".cache", "depward"));
  expect(defaultCacheDir({}, "darwin", "/h")).toBe(join("/h", "Library", "Caches", "depward"));
  expect(defaultCacheDir({ LOCALAPPDATA: "/l" }, "win32", "/h")).toBe(join("/l", "depward", "Cache"));
});
