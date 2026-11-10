// Tarball checks against recorded fixtures (fixtures/registry/). Offline; package code
// is never executed.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { SIGNAL_SEVERITY } from "@depward/analyzer";
import { DepwardError, type RegistryClient, type VersionMeta } from "@depward/core";
import { createFixtureRegistryClient, packTarball } from "@depward/core/testing";
import { describe, expect, test } from "vitest";
import { checkPackage, checkTarball, createGateData } from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../../fixtures/registry", import.meta.url));
const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const data = createGateData([{ name: "depward-fixture-stable", weeklyDownloads: 1_234_567 }], []);

const fixtures = () => createFixtureRegistryClient(FIXTURES);
const ids = (r: { findings: { id: string }[] }): string[] => r.findings.map((f) => f.id).toSorted();

async function metaOf(name: string, version: string): Promise<VersionMeta> {
  const meta = await fixtures().versionMeta(name, version);
  if (!meta) throw new Error(`fixture ${name}@${version} missing`);
  return meta;
}

function opts(extra: Record<string, unknown> = {}) {
  return { registry: fixtures(), data, now: () => NOW, ...extra };
}

/** A registry whose tarball() serves the given bytes, for archives built in the test. */
function serving(bytes: Uint8Array): RegistryClient {
  return { ...fixtures(), tarball: () => Promise.resolve(bytes) };
}

describe("checkTarball", () => {
  test("a clean package has a profile and no findings", async () => {
    const r = await checkTarball(await metaOf("depward-fixture-stable", "2.0.0"), { registry: fixtures() });
    expect(r.errors).toEqual([]);
    expect(r.findings).toEqual([]);
    expect(r.profile?.files.map((f) => f.path)).toEqual(["index.js", "package.json"]);
  });

  test("a token-stealing postinstall maps each analyzer signal to a finding", async () => {
    const r = await checkTarball(await metaOf("depward-fixture-takeover", "1.1.0"), { registry: fixtures() });
    expect(r.errors).toEqual([]);
    expect(ids(r)).toEqual(["env-exfil-pattern", "env-sensitive-read", "hardcoded-endpoint", "install-script", "install-script-network"]);
    const exfil = r.findings[0];
    expect(exfil).toMatchObject({ id: "env-exfil-pattern", severity: "critical", package: "depward-fixture-takeover", version: "1.1.0" });
    expect(exfil?.evidence[0]).toMatchObject({ file: "setup.js", line: 2 });
    expect(exfil?.docsUrl).toMatch(/findings\.md#env-exfil-pattern$/);
    expect(r.profile?.scripts).toEqual({ postinstall: "node setup.js" });
    expect(r.profile?.envKeys).toEqual(["NPM_TOKEN"]);
  });

  test("findings use the requested name and version, not the archive's own package.json", async () => {
    const bytes = packTarball([
      { path: "package.json", data: '{ "name": "lodash", "version": "9.9.9", "scripts": { "preinstall": "node x.js" } }' },
      { path: "x.js", data: "module.exports = 1;\n" },
    ]);
    const r = await checkTarball(await metaOf("depward-fixture-stable", "2.0.0"), { registry: serving(bytes) });
    expect(ids(r)).toEqual(["install-script"]);
    expect(r.findings[0]).toMatchObject({ package: "depward-fixture-stable", version: "2.0.0" });
  });
});

describe("tarball-unsafe", () => {
  test("a path-traversal entry", async () => {
    const r = await checkTarball(await metaOf("depward-fixture-unsafe", "1.0.0"), { registry: fixtures() });
    expect(r.errors).toEqual([]);
    expect(r.profile).toBeNull();
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ id: "tarball-unsafe", severity: "high", package: "depward-fixture-unsafe", version: "1.0.0" });
    expect(r.findings[0]?.evidence[0]?.detail).toContain('path contains ".."');
  });

  test("a corrupt archive", async () => {
    const r = await checkTarball(await metaOf("depward-fixture-stable", "2.0.0"), {
      registry: serving(new Uint8Array([0x1f, 0x8b, 1, 2, 3, 4, 5, 6, 7, 8])),
    });
    expect(ids(r)).toEqual(["tarball-unsafe"]);
    expect(r.errors).toEqual([]);
  });

  test("an archive over the size or entry limits", async () => {
    const meta = await metaOf("depward-fixture-stable", "2.0.0");
    const bySize = await checkTarball(meta, { registry: fixtures(), tarLimits: { maxCompressedBytes: 10 } });
    expect(ids(bySize)).toEqual(["tarball-unsafe"]);
    expect(bySize.findings[0]?.evidence[0]?.detail).toContain("limit");
    const byFiles = await checkTarball(meta, { registry: fixtures(), analyze: { maxFiles: 1 } });
    expect(ids(byFiles)).toEqual(["tarball-unsafe"]);
  });

  test("a package.json that isn't an object", async () => {
    const bytes = packTarball([{ path: "package.json", data: "[1, 2, 3]" }]);
    const r = await checkTarball(await metaOf("depward-fixture-stable", "2.0.0"), { registry: serving(bytes) });
    expect(ids(r)).toEqual(["tarball-unsafe"]);
  });
});

describe("tarball-integrity-mismatch", () => {
  test("bytes that don't match the published integrity are critical", async () => {
    const real = await metaOf("depward-fixture-stable", "2.0.0");
    const tampered: VersionMeta = {
      ...real,
      dist: { ...real.dist, integrity: `sha512-${"A".repeat(86)}==`, shasum: "0".repeat(40) },
    };
    const r = await checkTarball(tampered, { registry: fixtures() });
    expect(r.errors).toEqual([]);
    expect(r.profile).toBeNull();
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ id: "tarball-integrity-mismatch", severity: "critical", version: "2.0.0" });
    expect(r.findings[0]?.message).toContain("may have been tampered with");
  });
});

describe("transient failures are errors, not findings", () => {
  test("a network failure", async () => {
    const registry: RegistryClient = { ...fixtures(), tarball: () => Promise.reject(new DepwardError("TIMEOUT", "slow")) };
    const r = await checkTarball(await metaOf("depward-fixture-stable", "2.0.0"), { registry });
    expect(r.findings).toEqual([]);
    expect(r.errors.map((e) => e.code)).toEqual(["TIMEOUT"]);
  });

  test("a missing tarball (HTTP 404)", async () => {
    // depward-fixture-stable@1.1.0 has no tarball fixture, so the fixture fetch returns 404.
    const r = await checkTarball(await metaOf("depward-fixture-stable", "1.1.0"), { registry: fixtures() });
    expect(r.findings).toEqual([]);
    expect(r.errors.map((e) => e.code)).toEqual(["NETWORK"]);
  });

  test("non-depward errors are wrapped as INTERNAL", async () => {
    const registry: RegistryClient = { ...fixtures(), tarball: () => Promise.reject(new Error("boom")) };
    const r = await checkTarball(await metaOf("depward-fixture-stable", "2.0.0"), { registry });
    expect(r.errors[0]).toBeInstanceOf(DepwardError);
    expect(r.errors[0]?.code).toBe("INTERNAL");
  });
});

describe("checkPackage", () => {

  test("combines registry and tarball findings, sorted", async () => {
    const r = await checkPackage({ name: "depward-fixture-takeover", range: "^1.0.0" }, opts());
    expect(r.version).toBe("1.1.0");
    expect(r.errors).toEqual([]);
    expect(r.findings.map((f) => f.id)).toEqual([
      "env-exfil-pattern",
      "env-sensitive-read",
      "install-script-network",
      "provenance-dropped",
      "install-script",
      "publisher-changed",
      "version-too-new",
      "maintainer-added-recently",
      "hardcoded-endpoint",
    ]);
    expect(r.profile?.scripts.postinstall).toBe("node setup.js");
    expect(r.suggestion).toEqual({ version: "1.0.5" });
  });

  test("a clean package stays clean end to end", async () => {
    const r = await checkPackage({ name: "depward-fixture-stable", range: "latest" }, opts());
    expect(r.findings).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(r.profile).not.toBeNull();
  });

  test("no tarball is fetched when no version resolves", async () => {
    const registry = fixtures();
    const r = await checkPackage({ name: "depward-fixture-missing", range: "latest" }, opts({ registry }));
    expect(r.findings.map((f) => f.id)).toEqual(["package-not-found"]);
    expect(r.profile).toBeNull();
    expect(registry.requests.some((q) => q.url.endsWith(".tgz"))).toBe(false);
  });

  test("tarball: false skips the download", async () => {
    const registry = fixtures();
    const r = await checkPackage({ name: "depward-fixture-takeover", range: "^1.0.0" }, opts({ registry, tarball: false }));
    expect(r.findings.map((f) => f.id)).not.toContain("env-exfil-pattern");
    expect(r.profile).toBeNull();
    expect(registry.requests.some((q) => q.url.endsWith(".tgz"))).toBe(false);
  });

  test("errors from both stages are kept", async () => {
    const real = fixtures();
    const registry: RegistryClient = {
      ...real,
      weeklyDownloads: () => Promise.reject(new DepwardError("NETWORK", "downloads down")),
      tarball: () => Promise.reject(new DepwardError("TIMEOUT", "slow")),
    };
    const r = await checkPackage({ name: "depward-fixture-stable", range: "latest" }, opts({ registry }));
    expect(r.errors.map((e) => e.code)).toEqual(["NETWORK", "TIMEOUT"]);
  });
});

describe("finding catalog", () => {
  test("tarball finding IDs and every analyzer signal have entries in docs/findings.md", () => {
    const catalog = readFileSync(new URL("../../../docs/findings.md", import.meta.url), "utf8");
    for (const id of ["tarball-integrity-mismatch", "tarball-unsafe", ...Object.keys(SIGNAL_SEVERITY)]) {
      expect(catalog, id).toMatch(new RegExp(`^### ${id}\\r?$`, "m"));
    }
  });
});
