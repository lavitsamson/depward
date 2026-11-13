import { defaultConfig } from "@depward/core";
import { createPolicy } from "@depward/gate";
import { describe, expect, test } from "vitest";
import { capsCheckExitCode, compareObserved, type CapsLockfile, type ObservedFile } from "../src/index.ts";

const approved = (...capabilities: string[]) => ({ capabilities, approvedBy: "static", approvedAt: "2026-11-01" });
const CAPS: CapsLockfile = {
  version: 1,
  packages: { "orm-client@1.0.0": approved("crypto", "fs"), "web-framework@0.9.0": approved("fs", "net") },
};
const OBSERVED: ObservedFile = {
  version: 1,
  packages: {
    "orm-client@1.0.0": { crypto: { count: 10, members: ["crypto.randomUUID"] }, env: { count: 1, members: ["process.env.PRISMA_API_KEY"] }, fs: { count: 21, members: ["fs.readFileSync"] } },
    "web-framework@1.0.0": { fs: { count: 10, members: ["fs.createReadStream"] }, net: { count: 1, members: ["http.Server"] } },
    "helper@2.0.0": { child_process: { count: 1, members: ["child_process.spawn"] } },
  },
};

describe("compareObserved", () => {
  test("reports observed capabilities the reference entry doesn't list", () => {
    const r = compareObserved(OBSERVED, CAPS);
    expect(r.packages.map((p) => [p.kind, p.name, p.from ?? null, p.to, p.risk, p.findings.map((f) => f.message)])).toEqual([
      ["added", "helper", null, "2.0.0", "high", ["used child_process at runtime, which is not approved: helper has no entry in the capability lockfile"]],
      ["updated", "orm-client", "1.0.0", "1.0.0", "medium", ["used env at runtime, which is not approved: its entry in the capability lockfile does not list it"]],
    ]);
    expect(r.packages[1]?.findings[0]?.evidence).toEqual([{ snippet: "process.env.PRISMA_API_KEY" }, { detail: "1 use observed" }]);
    expect(r.counts).toEqual({ checked: 3, unapproved: 2 });
    expect(r.risk).toBe("high");
    expect(capsCheckExitCode(r, "critical")).toBe(20);
  });

  test("passes when everything observed is approved (a newer version uses the highest entry)", () => {
    const r = compareObserved({ version: 1, packages: { "web-framework@1.0.0": OBSERVED.packages["web-framework@1.0.0"] ?? {} } }, CAPS);
    expect(r.packages).toEqual([]);
    expect(capsCheckExitCode(r, "critical")).toBe(0);
  });

  test("the config applies", () => {
    const policy = createPolicy({ ...defaultConfig(), allow: ["helper"], policy: { "caps-observed-unapproved": "allow" } });
    const r = compareObserved(OBSERVED, CAPS, { policy });
    expect(r.packages.every((p) => p.findings.length === 0)).toBe(true);
    expect(r.counts.unapproved).toBe(0);
  });
});
