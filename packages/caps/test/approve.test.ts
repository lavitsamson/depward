// `approveCapabilities` end to end against the in-memory fake registry.

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDepwardError } from "@depward/core";
import { preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { approveCapabilities, checkCapabilities, parseTarget, type ApproveOptions, type CapsLockfile } from "../src/index.ts";
import { NOW, lock as lockIn, registry, type FakeRegistry, type Locked } from "./helpers.ts";

let dir: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-caps-approve-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const lock = (reg: FakeRegistry, packages: Record<string, Locked>) => lockIn(dir, reg, packages);
const approve = (reg: FakeRegistry, extra: Partial<ApproveOptions>) =>
  approveCapabilities({ cwd: dir, registry: reg.client, caps: null, targets: [], by: "alice", now: () => NOW, ...extra });
const OLD: CapsLockfile = {
  version: 1,
  packages: {
    "fx-net@1.0.0": { capabilities: ["net"], approvedBy: "static", approvedAt: "2026-11-01" },
    "fx-files@1.0.0": { capabilities: ["fs"], approvedBy: "static", approvedAt: "2026-11-01" },
  },
};

describe("parseTarget", () => {
  test.each([
    ["left-pad", { name: "left-pad" }],
    ["left-pad@1.3.0", { name: "left-pad", version: "1.3.0" }],
    ["@scope/x", { name: "@scope/x" }],
    ["@scope/x@2.0.0", { name: "@scope/x", version: "2.0.0" }],
  ])("%s", (arg, want) => {
    expect(parseTarget(arg)).toEqual(want);
  });
});

describe("approveCapabilities", () => {
  test("approves every capability of the locked version and leaves other entries alone", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0", "fx-files": "1.0.0" });
    const r = await approve(reg, { caps: OLD, targets: [{ name: "fx-net" }], reason: "spawns its helper binary" });
    expect(r.errors).toEqual([]);
    expect(r.approved).toEqual([{ key: "fx-net@2.0.0", capabilities: ["child_process", "net"], unapproved: [], notDetected: [] }]);
    expect(r.lockfile.packages).toEqual({
      ...OLD.packages,
      "fx-net@2.0.0": { capabilities: ["child_process", "net"], approvedBy: "alice", approvedAt: "2026-11-13", reason: "spawns its helper binary" },
    });
    const after = await checkCapabilities({ cwd: dir, registry: reg.client, caps: r.lockfile });
    expect(after.counts.unapproved).toBe(0);
  });

  test("--cap approves only the named capabilities on top of the reference entry", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    const r = await approve(reg, { caps: { version: 1, packages: {} }, targets: [{ name: "fx-net", version: "2.0.0" }], capabilities: ["net"] });
    expect(r.approved).toEqual([{ key: "fx-net@2.0.0", capabilities: ["net"], unapproved: ["child_process"], notDetected: [] }]);
    const withRef = await approve(reg, { caps: OLD, targets: [{ name: "fx-net" }], capabilities: ["child_process"] });
    expect(withRef.approved[0]?.capabilities).toEqual(["child_process", "net"]);
  });

  test("--cap may approve a capability static analysis doesn't see (for runtime enforcement); an unknown name throws", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": "1.0.0" });
    const r = await approve(reg, { targets: [{ name: "fx-files" }], capabilities: ["net"] });
    expect(r.errors).toEqual([]);
    expect(r.approved).toEqual([{ key: "fx-files@1.0.0", capabilities: ["net"], unapproved: ["fs"], notDetected: ["net"] }]);
    await expect(approve(reg, { targets: [{ name: "fx-files" }], capabilities: ["network"] })).rejects.toSatisfy(
      (e) => isDepwardError(e, "INVALID_ARGUMENT") && e.message.startsWith('unknown capability "network"'),
    );
  });

  test("a package or version that isn't locked throws", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": "1.0.0" });
    await expect(approve(reg, { targets: [{ name: "fx-net" }] })).rejects.toThrow("fx-net is not locked as a registry package");
    await expect(approve(reg, { targets: [{ name: "fx-files", version: "2.0.0" }] })).rejects.toThrow("fx-files@2.0.0 is not locked");
  });

  test("a version without capabilities is recorded without approval fields", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0" });
    const r = await approve(reg, { targets: [{ name: "fx-pure" }] });
    expect(r.lockfile.packages).toEqual({ "fx-pure@1.0.0": { capabilities: [] } });
  });
});
