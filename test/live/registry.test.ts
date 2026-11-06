// Opt-in: hits the real npm registry. Run with `pnpm test:live`.
import { describe, expect, test } from "vitest";
import { createMemoryCache, createRegistryClient, npmConfigFrom } from "../../packages/core/src/index.ts";

const client = createRegistryClient({ cache: createMemoryCache(), npmConfig: npmConfigFrom(), timeoutMs: 30_000 });

describe("live npm registry", () => {
  test("full packument includes time, maintainers, and _npmUser", async () => {
    const doc = await client.packument("semver");
    expect(doc).not.toBeNull();
    const latest = doc!["dist-tags"]["latest"]!;
    expect(doc!.time[latest]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(doc!.maintainers?.length).toBeGreaterThan(0);
    expect(doc!.versions[latest]?._npmUser?.name).toBeTruthy();
  });

  test("scoped packument and downloads", async () => {
    expect((await client.packument("@types/node"))?.name).toBe("@types/node");
    expect(await client.weeklyDownloads("@types/node")).toBeGreaterThan(1_000_000);
    expect(await client.weeklyDownloads("semver")).toBeGreaterThan(1_000_000);
  });

  test("unknown packages are null", async () => {
    expect(await client.packument("depward-definitely-not-a-real-package-7f3a9c")).toBeNull();
    expect(await client.weeklyDownloads("depward-definitely-not-a-real-package-7f3a9c")).toBeNull();
  });

  test("attestations are detected on a package published with provenance", async () => {
    const att = await client.attestations("sigstore", "latest");
    expect(att?.url).toMatch(/^https:\/\/registry\.npmjs\.org\/-\/npm\/v1\/attestations\//);
    expect(att?.provenancePredicateType).toMatch(/^https:\/\/slsa\.dev\/provenance\//);
  });

  test("tarball download is integrity-verified", async () => {
    const meta = await client.versionMeta("semver", "7.6.0");
    const bytes = await client.tarball(meta!);
    expect([bytes[0], bytes[1]]).toEqual([0x1f, 0x8b]);
  });
});
