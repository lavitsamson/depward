import { describe, expect, test } from "vitest";
import { isDeprecated, isPrerelease, publishTime, resolveVersion, type Packument, type VersionMeta } from "../src/index.ts";

function meta(version: string, extra: Partial<VersionMeta> = {}): VersionMeta {
  return { name: "pkg", version, dist: { tarball: `https://registry.npmjs.org/pkg/-/pkg-${version}.tgz` }, ...extra };
}

function packument(
  versions: Record<string, Partial<VersionMeta> | null>,
  tags: Record<string, string>,
  time: Record<string, string> = {},
): Packument {
  const v: Record<string, VersionMeta> = {};
  for (const [k, extra] of Object.entries(versions)) v[k] = meta(k, extra ?? {});
  return { name: "pkg", "dist-tags": tags, versions: v, time };
}

const doc = packument(
  {
    "1.0.0": null,
    "1.2.0": null,
    "1.3.0": { deprecated: "broken" },
    "2.0.0": null,
    "2.1.0-beta.1": null,
    "3.0.0": null,
  },
  { latest: "2.0.0", beta: "2.1.0-beta.1", next: "3.0.0" },
  {
    created: "2020-01-01T00:00:00.000Z",
    "1.0.0": "2020-01-01T00:00:00.000Z",
    "1.2.0": "2020-06-01T00:00:00.000Z",
    "1.3.0": "2021-01-01T00:00:00.000Z",
    "2.0.0": "2022-01-01T00:00:00.000Z",
    "2.1.0-beta.1": "2022-02-01T00:00:00.000Z",
    "3.0.0": "2023-01-01T00:00:00.000Z",
  },
);

describe("resolveVersion", () => {
  test.each([
    ["latest", "2.0.0"],
    ["", "2.0.0"],
    ["*", "2.0.0"],
    ["beta", "2.1.0-beta.1"],
    ["next", "3.0.0"],
    ["1.0.0", "1.0.0"],
    ["=1.2.0", "1.2.0"],
    ["v1.2.0", "1.2.0"],
    ["^1.0.0", "1.2.0"], // 1.3.0 is deprecated, so the highest non-deprecated wins
    ["~1.3.0", "1.3.0"], // ...unless only deprecated versions match
    [">=2", "2.0.0"], // latest satisfies, so it wins over 3.0.0
    ["^3", "3.0.0"],
    ["2.1.0-beta.1", "2.1.0-beta.1"],
    ["^2.1.0-beta.0", "2.1.0-beta.1"],
    [" ^1 ", "1.2.0"],
  ])("%j → %s", (spec, expected) => {
    expect(resolveVersion(doc, spec)?.version).toBe(expected);
  });

  test.each(["^4", "9.9.9", "no-such-tag", "not a range !!", "^2.1.0"])("%j → null", (spec) => {
    expect(resolveVersion(doc, spec)).toBeNull();
  });

  test("dist-tags are own properties only", () => {
    expect(resolveVersion(doc, "constructor")).toBeNull();
    expect(resolveVersion(doc, "__proto__")).toBeNull();
  });

  test("a tag pointing at a missing version resolves to null", () => {
    expect(resolveVersion(packument({ "1.0.0": null }, { latest: "1.0.1" }), "latest")).toBeNull();
  });

  test("publishedBefore filters out newer versions", () => {
    const before = Date.parse("2022-06-01T00:00:00.000Z");
    expect(resolveVersion(doc, "*", { publishedBefore: before })?.version).toBe("2.0.0");
    expect(resolveVersion(doc, "^3", { publishedBefore: before })).toBeNull();
    expect(resolveVersion(doc, "next", { publishedBefore: before })).toBeNull();
    const early = Date.parse("2021-06-01T00:00:00.000Z");
    // latest (2.0.0) is too new, so fall back to the highest old-enough version.
    expect(resolveVersion(doc, "*", { publishedBefore: early })?.version).toBe("1.2.0");
  });

  test("publishedBefore excludes versions without a publish time", () => {
    const noTime = packument({ "1.0.0": null }, { latest: "1.0.0" });
    expect(resolveVersion(noTime, "*", { publishedBefore: Date.now() })).toBeNull();
  });
});

describe("publishTime / isPrerelease / isDeprecated", () => {
  test("reads times and ignores invalid ones", () => {
    expect(publishTime(doc, "1.0.0")).toBe(Date.parse("2020-01-01T00:00:00.000Z"));
    expect(publishTime(doc, "9.9.9")).toBeNull();
    expect(publishTime({ ...doc, time: { "1.0.0": "garbage" } }, "1.0.0")).toBeNull();
    expect(publishTime(doc, "hasOwnProperty")).toBeNull();
  });

  test("isPrerelease", () => {
    expect(isPrerelease("1.0.0-beta.1")).toBe(true);
    expect(isPrerelease("8.0.0-alpha.14")).toBe(true);
    expect(isPrerelease("1.0.0")).toBe(false);
    expect(isPrerelease("1.0.0+build.5")).toBe(false);
    expect(isPrerelease("not-a-version")).toBe(false);
  });

  test("deprecated means a non-empty string", () => {
    expect(isDeprecated(meta("1.0.0", { deprecated: "x" }))).toBe(true);
    expect(isDeprecated(meta("1.0.0", { deprecated: "" }))).toBe(false);
    expect(isDeprecated(meta("1.0.0"))).toBe(false);
  });
});
