// `checkCapabilities` end to end against the in-memory fake registry.

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig, isDepwardError } from "@depward/core";
import { createPolicy, preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { capsCheckExitCode, checkCapabilities, referenceIndex, type CapsLockfile, type CheckOptions } from "../src/index.ts";
import { lock as lockIn, registry, type FakeRegistry, type Locked } from "./helpers.ts";

let dir: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-caps-check-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const lock = (reg: FakeRegistry, packages: Record<string, Locked>) => lockIn(dir, reg, packages);
const caps = (packages: CapsLockfile["packages"]): CapsLockfile => ({ version: 1, packages });
const check = (reg: FakeRegistry, c: CapsLockfile, extra: Partial<CheckOptions> = {}) => checkCapabilities({ cwd: dir, registry: reg.client, caps: c, ...extra });
const approved = (...capabilities: string[]) => ({ capabilities, approvedBy: "static", approvedAt: "2026-11-01" });

describe("referenceIndex", () => {
  const ref = referenceIndex(caps({ "a@1.0.0": approved("fs"), "a@1.10.0": approved("net"), "a@1.9.0": approved("env"), "b@1.0.0": approved() }));

  test("prefers the exact entry, else the highest version of the name", () => {
    expect(ref("a", "1.9.0")?.key).toBe("a@1.9.0");
    expect(ref("a", "2.0.0")?.key).toBe("a@1.10.0");
    expect(ref("a", "0.1.0")?.key).toBe("a@1.10.0");
    expect(ref("c", "1.0.0")).toBeNull();
  });
});

describe("checkCapabilities", () => {
  test("approved capabilities pass, and quiet packages are left out of the report", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": "1.0.0", "fx-pure": "1.0.0" });
    const r = await check(reg, caps({ "fx-files@1.0.0": approved("fs"), "fx-pure@1.0.0": approved() }));
    expect(r.packages).toEqual([]);
    expect(r.counts).toEqual({ checked: 2, unapproved: 0 });
    expect(r.risk).toBe("info");
    expect(capsCheckExitCode(r, "critical")).toBe(0);
  });

  test("an update that adds capabilities is compared with the most recent approved entry", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    const r = await check(reg, caps({ "fx-net@1.0.0": approved("net") }));
    expect(r.packages).toHaveLength(1);
    const [p] = r.packages;
    expect(p).toMatchObject({ kind: "updated", name: "fx-net", from: "1.0.0", to: "2.0.0", lockfiles: ["package-lock.json"], risk: "high" });
    expect(p?.line).toBeGreaterThan(1);
    expect(p?.findings.map((f) => [f.id, f.severity, f.message])).toEqual([
      ["caps-unapproved", "high", "uses child_process, which is not approved: the approved entry for 1.0.0 does not list it"],
    ]);
    expect(p?.findings[0]?.evidence[0]).toMatchObject({ file: "index.js", line: 1 });
    expect(r.counts.unapproved).toBe(1);
    expect(capsCheckExitCode(r, "critical")).toBe(20);
  });

  test("a package with no entry has nothing approved; one without capabilities passes", async () => {
    const reg = registry();
    await lock(reg, { "@fx/scoped": "3.0.0", "fx-pure": "1.0.0" });
    const r = await check(reg, caps({}));
    expect(r.packages.map((p) => [p.kind, p.name, p.risk, p.findings.map((f) => f.message)])).toEqual([
      ["added", "@fx/scoped", "medium", ["uses env, which is not approved: @fx/scoped has no entry in the capability lockfile"]],
    ]);
  });

  test("an exact entry that lists fewer capabilities fails on the rest", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    const r = await check(reg, caps({ "fx-net@2.0.0": approved("child_process") }));
    expect(r.packages[0]).toMatchObject({ kind: "updated", from: "2.0.0", to: "2.0.0" });
    expect(r.packages[0]?.findings.map((f) => f.message)).toEqual(["uses net, which is not approved: its entry in the capability lockfile does not list it"]);
  });

  test("non-registry sources are reported; local ones are skipped", async () => {
    const reg = registry();
    await lock(reg, {
      "fx-pure": "1.0.0",
      "local-lib": { resolved: "packages/local-lib", link: true },
      "fx-git": { version: "1.0.0", resolved: "git+ssh://git@example.invalid/fx-git.git#0123456789abcdef0123456789abcdef01234567" },
    });
    const r = await check(reg, caps({ "fx-pure@1.0.0": approved() }));
    expect(r.packages.map((p) => [p.kind, p.name, p.findings.map((f) => f.id)])).toEqual([["non-registry", "fx-git", ["non-registry-source"]]]);
    expect(r.skipped).toHaveLength(1);
    expect(r.skipped[0]).toMatch(/^local-lib@/);
    expect(capsCheckExitCode(r, "critical")).toBe(0);
    expect(capsCheckExitCode(r, "medium")).toBe(20);
  });

  test("a lockfile integrity mismatch is a critical finding", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": { version: "1.0.0", resolved: "https://registry.npmjs.org/fx-pure/-/fx-pure-1.0.0.tgz", integrity: reg.integrity("fx-net", "1.0.0") } });
    const r = await check(reg, caps({ "fx-pure@1.0.0": approved() }));
    expect(r.packages[0]?.findings.map((f) => f.id)).toEqual(["lockfile-integrity-mismatch"]);
    expect(r.risk).toBe("critical");
    expect(capsCheckExitCode(r, "critical")).toBe(20);
  });

  test("a version missing from the registry is an error (exit 1)", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": { version: "9.9.9", resolved: "https://registry.npmjs.org/fx-files/-/fx-files-9.9.9.tgz", integrity: "sha512-AAAA" } });
    const r = await check(reg, caps({}));
    expect(r.packages[0]?.errors.map((e) => e.code)).toEqual(["NOT_FOUND"]);
    expect(capsCheckExitCode(r, "critical")).toBe(1);
  });

  test("the config applies: an allow-listed package's findings don't count; a deny-listed one is critical", async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0", "fx-files": "1.0.0" });
    const policy = createPolicy({ ...defaultConfig(), allow: ["fx-net"], deny: ["fx-files"] });
    const r = await check(reg, caps({ "fx-net@1.0.0": approved("net"), "fx-files@1.0.0": approved("fs") }), { policy });
    const net = r.packages.find((p) => p.name === "fx-net");
    expect(net?.findings).toEqual([]);
    expect(net?.allowedFindings?.map((f) => f.id)).toEqual(["caps-unapproved"]);
    expect(r.packages.find((p) => p.name === "fx-files")?.risk).toBe("critical");
    expect(r.counts.unapproved).toBe(0);
    expect(capsCheckExitCode(r, "critical")).toBe(20);
  });

  test('a config policy override of caps-unapproved to "allow" keeps findings visible but not counted', async () => {
    const reg = registry();
    await lock(reg, { "fx-net": "2.0.0" });
    const policy = createPolicy({ ...defaultConfig(), policy: { "caps-unapproved": "allow" } });
    const r = await check(reg, caps({ "fx-net@1.0.0": approved("net") }), { policy });
    expect(r.packages[0]?.findings).toEqual([]);
    expect(r.packages[0]?.allowedFindings?.map((f) => f.id)).toEqual(["caps-unapproved"]);
    expect(capsCheckExitCode(r, "critical")).toBe(0);
  });

  test("no lockfile is NOT_FOUND", async () => {
    await expect(check(registry(), caps({}))).rejects.toSatisfy((e) => isDepwardError(e, "NOT_FOUND"));
  });
});
