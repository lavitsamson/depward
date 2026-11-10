import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { CONFIG_FILE, defaultConfig, isDepwardError, loadConfig, parseConfig } from "../src/index.ts";

const code = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (err) {
    return isDepwardError(err) ? err.code : "not a DepwardError";
  }
  return undefined;
};

describe("parseConfig", () => {
  test("accepts the documented shape", () => {
    const config = parseConfig({
      $schema: "https://example.invalid/schema.json",
      policy: { "version-too-new": "allow", "install-script": "deny" },
      thresholds: { minVersionAgeDays: 3, minPackageAgeDays: 14, minWeeklyDownloads: 0 },
      allow: ["@myorg/*", " left-pad "],
      deny: ["event-stream@3.3.6"],
      onError: "deny",
      registry: "https://npm.example.com",
    }, "test.json");
    expect(config).toEqual({
      policy: { "version-too-new": "allow", "install-script": "deny" },
      thresholds: { minVersionAgeDays: 3, minPackageAgeDays: 14, minWeeklyDownloads: 0 },
      allow: ["@myorg/*", "left-pad"],
      deny: ["event-stream@3.3.6"],
      onError: "deny",
      registry: "https://npm.example.com/",
      source: "test.json",
    });
  });

  test("an empty object gives the defaults; onError defaults to ask, never allow", () => {
    expect(parseConfig({}, "x")).toEqual({ ...defaultConfig(), source: "x" });
    expect(defaultConfig().onError).toBe("ask");
  });

  test.each([
    ["not an object", []],
    ["a typo'd key", { denny: ["x"] }],
    ["policy not an object", { policy: ["x"] }],
    ["an unknown action", { policy: { "version-too-new": "warn" } }],
    ["a key that is not a finding ID", { policy: { "Version Too New": "allow" } }],
    ["an unknown threshold", { thresholds: { minAgeDays: 1 } }],
    ["a negative threshold", { thresholds: { minVersionAgeDays: -1 } }],
    ["a string threshold", { thresholds: { minVersionAgeDays: "7" } }],
    ["a non-finite threshold", { thresholds: { minWeeklyDownloads: Number.POSITIVE_INFINITY } }],
    ["allow not an array", { allow: "@myorg/*" }],
    ["an empty list entry", { deny: ["  "] }],
    ["a non-string list entry", { deny: [42] }],
    ["a bad onError", { onError: "ignore" }],
    ["a non-http registry", { registry: "file:///etc/passwd" }],
    ["an unparseable registry", { registry: "not a url" }],
  ])("rejects %s with INVALID_CONFIG", (_label, value) => {
    expect(code(() => parseConfig(value, "x"))).toBe("INVALID_CONFIG");
  });

  test("error messages name the source file", () => {
    expect(() => parseConfig({ onError: 1 }, "/repo/depward.config.json")).toThrow(/^\/repo\/depward\.config\.json: /);
  });
});

describe("loadConfig", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "depward-config-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  test("no file at all gives the defaults", async () => {
    expect(await loadConfig(dir)).toEqual(defaultConfig());
  });

  test("a package.json without a depward key gives the defaults", async () => {
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "app" }));
    expect(await loadConfig(dir)).toEqual(defaultConfig());
  });

  test("reads the depward key of package.json", async () => {
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "app", depward: { allow: ["@app/*"] } }));
    const config = await loadConfig(dir);
    expect(config.allow).toEqual(["@app/*"]);
    expect(config.source).toBe(`${join(dir, "package.json")} ("depward" key)`);
  });

  test("depward.config.json wins over package.json, and a BOM is tolerated", async () => {
    await writeFile(join(dir, "package.json"), JSON.stringify({ depward: { allow: ["from-pkg"] } }));
    await writeFile(join(dir, CONFIG_FILE), `﻿${JSON.stringify({ allow: ["from-file"] })}`);
    const config = await loadConfig(dir);
    expect(config.allow).toEqual(["from-file"]);
    expect(config.source).toBe(join(dir, CONFIG_FILE));
  });

  test("malformed JSON and invalid shapes are INVALID_CONFIG, not a silent fallback", async () => {
    await writeFile(join(dir, CONFIG_FILE), "{ allow: [ }");
    await expect(loadConfig(dir)).rejects.toMatchObject({ code: "INVALID_CONFIG" });
    await writeFile(join(dir, CONFIG_FILE), JSON.stringify({ deny: "x" }));
    await expect(loadConfig(dir)).rejects.toMatchObject({ code: "INVALID_CONFIG" });
  });

  test("an explicit path is read relative to cwd, and must exist", async () => {
    await writeFile(join(dir, "custom.json"), JSON.stringify({ onError: "deny" }));
    expect((await loadConfig(dir, { path: "custom.json" })).onError).toBe("deny");
    expect((await loadConfig("/", { path: join(dir, "custom.json") })).onError).toBe("deny");
    await expect(loadConfig(dir, { path: "missing.json" })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  test("an explicit package.json path needs a depward key", async () => {
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "app" }));
    await expect(loadConfig(dir, { path: "package.json" })).rejects.toMatchObject({ code: "INVALID_CONFIG" });
  });

  test("files over 1 MB are refused", async () => {
    await writeFile(join(dir, CONFIG_FILE), JSON.stringify({ allow: [], pad: "x".repeat(1024 * 1024) }));
    await expect(loadConfig(dir)).rejects.toMatchObject({ code: "INVALID_CONFIG", message: expect.stringMatching(/larger than/) });
  });
});
