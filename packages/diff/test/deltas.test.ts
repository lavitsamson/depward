import { describe, expect, test } from "vitest";
import { declaredDependencies, diffPackages, isLargeChange } from "../src/index.ts";
import { attested, meta, profile, type ProfileSpec } from "./helpers.ts";

function diff(a: ProfileSpec, b: ProfileSpec, metaA = meta(a.version ?? "1.0.0"), metaB = meta(b.version ?? "1.1.0")) {
  return diffPackages(profile({ version: "1.0.0", ...a }), profile({ version: "1.1.0", ...b }), metaA, metaB);
}

describe("capabilityDelta", () => {
  test("lists capabilities gained and lost, in CAPABILITIES order", () => {
    const d = diff({ caps: { fs: ["a.js"], crypto: ["a.js"] } }, { caps: { env: ["b.js"], fs: ["b.js"], net: ["b.js"] } });
    expect(d.capabilityDelta).toEqual({ added: ["net", "env"], removed: ["crypto"] });
  });

  test("a capability used in a different file is not new", () => {
    expect(diff({ caps: { fs: ["a.js"] } }, { caps: { fs: ["b.js"] } }).capabilityDelta).toEqual({ added: [], removed: [] });
  });
});

describe("signalDelta", () => {
  test("compares by id only, so a renamed bundle chunk does not re-flag", () => {
    const d = diff({ signals: [{ id: "high-entropy-string", file: "index.Ab12.js" }] }, { signals: [{ id: "high-entropy-string", file: "index.Zz99.js" }] });
    expect(d.signalDelta).toEqual({ added: [], removed: [] });
  });

  test("keeps every B signal of a new id, and every A signal of a dropped id", () => {
    const d = diff(
      { signals: [{ id: "minified-only" }] },
      { signals: [{ id: "obfuscation", file: "x.js" }, { id: "obfuscation", file: "y.js" }] },
    );
    expect(d.signalDelta.added.map((s) => s.evidence[0]?.file)).toEqual(["x.js", "y.js"]);
    expect(d.signalDelta.removed.map((s) => s.id)).toEqual(["minified-only"]);
  });
});

describe("scriptDelta", () => {
  test("records added, changed, and removed scripts", () => {
    const d = diff(
      { scripts: { install: "node-gyp rebuild", prepare: "tsc", postinstall: "node a.js" } },
      { scripts: { install: "node-gyp rebuild", preinstall: "node pre.js", postinstall: "node b.js" } },
    );
    expect(d.scriptDelta).toEqual({
      preinstall: { to: "node pre.js" },
      postinstall: { from: "node a.js", to: "node b.js" },
      prepare: { from: "tsc" },
    });
  });

  test("identical scripts produce no delta", () => {
    expect(diff({ scripts: { install: "x" } }, { scripts: { install: "x" } }).scriptDelta).toEqual({});
  });
});

describe("dependencyDelta", () => {
  test("merges dependency groups by name and reports range changes", () => {
    const d = diff(
      {},
      {},
      meta("1.0.0", { dependencies: { a: "^1", b: "^2", gone: "1" }, peerDependencies: { p: "*" } }),
      meta("1.1.0", { dependencies: { a: "^1", b: "^3" }, optionalDependencies: { opt: "1" }, peerDependencies: { p: "*", q: "2" } }),
    );
    expect(d.dependencyDelta).toEqual({ added: ["opt", "q"], removed: ["gone"], changed: ["b"] });
  });

  test("the first group wins for a name, and non-string ranges are ignored", () => {
    const m = meta("1.0.0", { dependencies: { a: "1" }, optionalDependencies: { a: "2", bad: 3 as unknown as string } });
    expect([...declaredDependencies(m)]).toEqual([["a", "1"]]);
  });

  test("a dependency moved between groups with the same range is unchanged", () => {
    const d = diff({}, {}, meta("1.0.0", { dependencies: { a: "1" } }), meta("1.1.0", { optionalDependencies: { a: "1" } }));
    expect(d.dependencyDelta).toEqual({ added: [], removed: [], changed: [] });
  });
});

describe("fileDelta", () => {
  test("reports added, removed, and largely changed files, sorted", () => {
    const d = diff(
      { files: [{ path: "keep.js" }, { path: "old.js" }, { path: "grow.js", size: 1000, sha256: "a".repeat(64) }, { path: "tweak.js", size: 1000, sha256: "a".repeat(64) }] },
      { files: [{ path: "keep.js" }, { path: "z.js" }, { path: "b.js" }, { path: "grow.js", size: 1600, sha256: "b".repeat(64) }, { path: "tweak.js", size: 1100, sha256: "b".repeat(64) }] },
    );
    expect(d.fileDelta).toEqual({ added: ["b.js", "z.js"], removed: ["old.js"], changedLarge: ["grow.js"] });
  });

  test("same hash never counts as changed, whatever the reported size", () => {
    const d = diff({ files: [{ path: "a.js", size: 10 }] }, { files: [{ path: "a.js", size: 1_000_000 }] });
    expect(d.fileDelta.changedLarge).toEqual([]);
  });

  test.each([
    [1000, 1500, false],
    [1000, 1501, true],
    [1000, 499, true],
    [10_000_000, 10_102_400, false],
    [10_000_000, 10_102_401, true],
    [0, 1, true],
  ])("isLargeChange(%i, %i) is %s", (a, b, want) => {
    expect(isLargeChange(a, b)).toBe(want);
  });
});

describe("endpoint and env deltas", () => {
  test("list only what is new in B", () => {
    const d = diff({ endpoints: ["https://a.example.com/"], envKeys: ["HOME"] }, { endpoints: ["https://a.example.com/", "https://b.example.com/"], envKeys: ["HOME", "NPM_TOKEN"] });
    expect(d.endpointDelta).toEqual({ added: ["https://b.example.com/"] });
    expect(d.envKeyDelta).toEqual({ added: ["NPM_TOKEN"] });
  });
});

describe("publisher and provenance deltas", () => {
  test("publisherDelta records a name change", () => {
    const d = diff({}, {}, meta("1.0.0"), meta("1.1.0", { _npmUser: { name: "mallory" } }));
    expect(d.publisherDelta).toEqual({ from: "alice", to: "mallory" });
  });

  test("no publisherDelta when a side has no publisher", () => {
    expect(diff({}, {}, meta("1.0.0", { _npmUser: {} }), meta("1.1.0", { _npmUser: { name: "x" } })).publisherDelta).toBeUndefined();
  });

  test("provenanceDelta is dropped, added, or absent", () => {
    expect(diff({}, {}, attested("1.0.0"), meta("1.1.0")).provenanceDelta).toBe("dropped");
    expect(diff({}, {}, meta("1.0.0"), attested("1.1.0")).provenanceDelta).toBe("added");
    expect(diff({}, {}, attested("1.0.0"), attested("1.1.0")).provenanceDelta).toBeUndefined();
  });
});

describe("input validation", () => {
  test("rejects profiles of different packages", () => {
    const b = { ...profile({ version: "1.1.0" }), name: "other" };
    expect(() => diffPackages(profile(), b, meta("1.0.0"), meta("1.1.0"))).toThrow(expect.objectContaining({ code: "INVALID_ARGUMENT" }));
  });

  test("rejects metadata that doesn't match the profile version", () => {
    expect(() => diffPackages(profile(), profile({ version: "1.1.0" }), meta("1.0.0"), meta("9.9.9"))).toThrow(expect.objectContaining({ code: "INVALID_ARGUMENT" }));
  });
});
