import type { LockfileEntry } from "@depward/core";
import { describe, expect, test } from "vitest";
import { compareVersions, mapLimit, planLockfile } from "../src/index.ts";

const e = (name: string, version: string, extra: Partial<LockfileEntry> = {}): LockfileEntry => ({
  name,
  version,
  source: "registry",
  integrity: `sha512-${name}${version}`,
  resolved: null,
  dev: null,
  optional: null,
  ...extra,
});
const pairs = (p: ReturnType<typeof planLockfile>) => p.updates.map((u) => `${u.after.name} ${u.before.version}→${u.after.version}`);

describe("planLockfile", () => {
  test("pairs a removed and an added version of the same name", () => {
    const p = planLockfile({ added: [e("a", "1.1.0"), e("new", "1.0.0")], removed: [e("a", "1.0.0"), e("gone", "1.0.0")], changed: [] });
    expect(pairs(p)).toEqual(["a 1.0.0→1.1.0"]);
    expect(p.checks).toEqual([{ kind: "added", entry: e("new", "1.0.0") }]);
  });

  test("with several versions, pairs within the same major first, then the highest left", () => {
    const p = planLockfile({
      added: [e("a", "2.1.0"), e("a", "1.5.0"), e("a", "4.0.0")],
      removed: [e("a", "1.4.0"), e("a", "1.2.0"), e("a", "2.0.0"), e("a", "3.0.0")],
      changed: [],
    });
    expect(pairs(p)).toEqual(["a 1.4.0→1.5.0", "a 2.0.0→2.1.0", "a 3.0.0→4.0.0"]);
  });

  test("an extra added version with nothing left to pair is a new check", () => {
    const p = planLockfile({ added: [e("a", "1.1.0"), e("a", "2.0.0")], removed: [e("a", "1.0.0")], changed: [] });
    expect(pairs(p)).toEqual(["a 1.0.0→1.1.0"]);
    expect(p.checks.map((c) => c.entry.version)).toEqual(["2.0.0"]);
  });

  test("routes entries by source", () => {
    const p = planLockfile({
      added: [e("g", "1.0.0", { source: "git" }), e("t", "1.0.0", { source: "tarball" }), e("l", "file:../l", { source: "link" }), e("w", "0.0.0", { source: "workspace" }), e("b", "1.0.0", { source: "bundled" })],
      removed: [e("g", "0.9.0")],
      changed: [],
    });
    expect(p.updates).toEqual([]);
    expect(p.nonRegistry.map((c) => c.entry.name)).toEqual(["g", "t"]);
    expect(p.skipped.map((x) => x.name)).toEqual(["b", "l", "w"]);
  });

  test("changed entries are re-checked only for an integrity or source change", () => {
    const p = planLockfile({
      added: [],
      removed: [],
      changed: [
        { before: e("i", "1.0.0"), after: e("i", "1.0.0", { integrity: "sha512-other" }) },
        { before: e("s", "1.0.0"), after: e("s", "1.0.0", { source: "tarball" }) },
        { before: e("d", "1.0.0"), after: e("d", "1.0.0", { dev: true }) },
        { before: e("n", "1.0.0", { integrity: null }), after: e("n", "1.0.0", { resolved: "x" }) },
      ],
    });
    expect(p.checks).toEqual([{ kind: "changed", entry: e("i", "1.0.0", { integrity: "sha512-other" }) }]);
    expect(p.nonRegistry.map((c) => [c.kind, c.entry.name])).toEqual([["changed", "s"]]);
  });
});

describe("compareVersions", () => {
  test.each([
    ["1.0.0", "1.0.1", -1],
    ["1.10.0", "1.9.0", 1],
    ["1.0.0-beta", "1.0.0", -1],
    ["1.0.0-alpha", "1.0.0-beta", -1],
    ["2.0.0", "2.0.0", 0],
    ["file:x", "1.0.0", -1],
  ])("%s vs %s", (a, b, sign) => {
    expect(Math.sign(compareVersions(a, b))).toBe(sign);
  });
});

describe("mapLimit", () => {
  test("keeps order and never exceeds the limit", async () => {
    let active = 0;
    let peak = 0;
    const out = await mapLimit([5, 1, 4, 2, 3, 0], 2, async (n) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, n));
      active--;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 40, 20, 30, 0]);
    expect(peak).toBe(2);
  });

  test("handles an empty list", async () => {
    expect(await mapLimit([], 8, async () => 1)).toEqual([]);
  });
});
