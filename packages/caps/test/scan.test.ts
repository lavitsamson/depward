// `scanCapabilities` end to end: a lockfile on disk and the in-memory fake registry. All
// packages are synthetic and inert; endpoints use example.invalid only.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createMemoryCache, isDepwardError } from "@depward/core";
import { preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { fakeRegistry, type FakeRegistry } from "../../diff/test/fake-registry.ts";
import { baselineEntry, capabilitiesOf, scanCapabilities, utcDate, type CapsLockfile, type ScanOptions } from "../src/index.ts";

const NOW = Date.parse("2026-11-13T22:30:00.000Z");

function registry(): FakeRegistry {
  return fakeRegistry({
    "fx-files": { versions: { "1.0.0": { files: { "index.js": 'const fs = require("fs");\nmodule.exports = (p) => fs.readFileSync(p, "utf8");\n' } } } },
    "fx-net": {
      versions: {
        "1.0.0": { files: { "index.js": 'module.exports = () => fetch("https://api.example.invalid/v1");\n' } },
        "2.0.0": { files: { "index.js": 'const cp = require("child_process");\nmodule.exports = () => { cp.execSync("id"); return fetch("https://api.example.invalid/v2"); };\n' } },
      },
    },
    "fx-pure": { versions: { "1.0.0": {} } },
    "@fx/scoped": { versions: { "3.0.0": { files: { "index.js": "module.exports = process.env.HOME;\n" } } } },
  });
}

let dir: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-caps-scan-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

type Locked = string | { version?: string; resolved?: string; integrity?: string; link?: boolean };

async function lock(reg: FakeRegistry, packages: Record<string, Locked>): Promise<void> {
  const out: Record<string, unknown> = { "": { name: "root" } };
  for (const [name, spec] of Object.entries(packages)) {
    if (typeof spec === "string") {
      const file = `${name.replace(/^@[^/]+\//, "")}-${spec}.tgz`;
      out[`node_modules/${name}`] = { version: spec, resolved: `https://registry.npmjs.org/${name}/-/${file}`, integrity: reg.integrity(name, spec) };
    } else {
      out[`node_modules/${name}`] = spec;
    }
  }
  await writeFile(join(dir, "package-lock.json"), JSON.stringify({ name: "root", lockfileVersion: 3, packages: out }, null, 2));
}

const scan = (reg: FakeRegistry, extra: Partial<ScanOptions> = {}) => scanCapabilities({ cwd: dir, registry: reg.client, now: () => NOW, ...extra });

describe("helpers", () => {
  test("utcDate uses UTC", () => {
    expect(utcDate(Date.parse("2026-11-13T23:59:59.000-05:00"))).toBe("2026-11-14");
  });

  test("capabilitiesOf lists capabilities with uses, sorted", () => {
    const use = { file: "index.js", line: 1, snippet: "" };
    const caps = { fs: [use], net: [], env: [use], crypto: [] } as unknown as Parameters<typeof capabilitiesOf>[0]["capabilities"];
    expect(capabilitiesOf({ capabilities: caps } as Parameters<typeof capabilitiesOf>[0])).toEqual(["env", "fs"]);
  });

  test("baselineEntry keeps an approval only for the same capability set", () => {
    const existing = { capabilities: ["net", "fs"], approvedBy: "alice", approvedAt: "2026-01-01", reason: "ok" };
    expect(baselineEntry(["fs", "net"], existing, "2026-11-13")).toEqual({ entry: { ...existing, capabilities: ["fs", "net"] }, kept: true });
    expect(baselineEntry(["fs"], existing, "2026-11-13")).toEqual({ entry: { capabilities: ["fs"], approvedBy: "static", approvedAt: "2026-11-13" }, kept: false });
    expect(baselineEntry([], undefined, "2026-11-13")).toEqual({ entry: { capabilities: [] }, kept: false });
  });
});

describe("scanCapabilities", () => {
  test("records each registry entry's capabilities; only entries with capabilities get an approval", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": "1.0.0", "fx-net": "1.0.0", "fx-pure": "1.0.0", "@fx/scoped": "3.0.0" });
    const r = await scan(reg);
    expect(r.errors).toEqual([]);
    expect(r.lockfiles).toEqual(["package-lock.json"]);
    expect(r.lockfile).toEqual({
      version: 1,
      packages: {
        "@fx/scoped@3.0.0": { capabilities: ["env"], approvedBy: "static", approvedAt: "2026-11-13" },
        "fx-files@1.0.0": { capabilities: ["fs"], approvedBy: "static", approvedAt: "2026-11-13" },
        "fx-net@1.0.0": { capabilities: ["net"], approvedBy: "static", approvedAt: "2026-11-13" },
        "fx-pure@1.0.0": { capabilities: [] },
      },
    });
    expect(r.counts).toEqual({ scanned: 4, withCapabilities: 3, kept: 0, dropped: 0 });
  });

  test("a re-scan keeps approvals of unchanged entries, re-baselines changed ones, drops unlocked ones", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": "1.0.0", "fx-net": "2.0.0" });
    const existing: CapsLockfile = {
      version: 1,
      packages: {
        "fx-files@1.0.0": { capabilities: ["fs"], approvedBy: "alice", approvedAt: "2026-10-01", reason: "reads config" },
        "fx-net@2.0.0": { capabilities: ["net"], approvedBy: "static", approvedAt: "2026-10-01" },
        "fx-net@1.0.0": { capabilities: ["net"], approvedBy: "static", approvedAt: "2026-10-01" },
      },
    };
    const r = await scan(reg, { existing });
    expect(r.lockfile.packages).toEqual({
      "fx-files@1.0.0": { capabilities: ["fs"], approvedBy: "alice", approvedAt: "2026-10-01", reason: "reads config" },
      "fx-net@2.0.0": { capabilities: ["child_process", "net"], approvedBy: "static", approvedAt: "2026-11-13" },
    });
    expect(r.counts).toEqual({ scanned: 2, withCapabilities: 2, kept: 1, dropped: 1 });
  });

  test("non-registry entries are skipped and listed", async () => {
    const reg = registry();
    await lock(reg, {
      "fx-pure": "1.0.0",
      "local-lib": { resolved: "packages/local-lib", link: true },
      "fx-git": { version: "1.0.0", resolved: "git+ssh://git@example.invalid/fx-git.git#0123456789abcdef0123456789abcdef01234567" },
    });
    const r = await scan(reg);
    expect(Object.keys(r.lockfile.packages)).toEqual(["fx-pure@1.0.0"]);
    expect(r.skipped.map((s) => [s.key.split("@")[0], s.source])).toEqual([
      ["fx-git", "git"],
      ["local-lib", "link"],
    ]);
    expect(reg.requests.some((u) => u.includes("fx-git") || u.includes("local-lib"))).toBe(false);
  });

  test("a version missing from the registry is an error, and other packages are still scanned", async () => {
    const reg = registry();
    await lock(reg, { "fx-pure": "1.0.0", "fx-files": { version: "9.9.9", resolved: "https://registry.npmjs.org/fx-files/-/fx-files-9.9.9.tgz", integrity: "sha512-AAAA" } });
    const r = await scan(reg);
    expect(r.errors.map((e) => [e.code, e.message])).toEqual([["NOT_FOUND", "fx-files@9.9.9: not in the registry"]]);
    expect(Object.keys(r.lockfile.packages)).toEqual(["fx-pure@1.0.0"]);
  });

  test("a lockfile integrity that disagrees with the registry is an error", async () => {
    const reg = registry();
    const other = reg.integrity("fx-net", "1.0.0");
    await lock(reg, { "fx-pure": { version: "1.0.0", resolved: "https://registry.npmjs.org/fx-pure/-/fx-pure-1.0.0.tgz", integrity: other } });
    const r = await scan(reg);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]?.code).toBe("INTEGRITY_MISMATCH");
    expect(r.errors[0]?.message).toMatch(/^fx-pure@1\.0\.0: package-lock\.json locks fx-pure@1\.0\.0 to a different tarball/);
  });

  test("uses the analysis cache", async () => {
    const reg = registry();
    await lock(reg, { "fx-files": "1.0.0", "fx-net": "1.0.0" });
    const analysisCache = createMemoryCache();
    await scan(reg, { analysisCache });
    const before = reg.requests.filter((u) => u.endsWith(".tgz")).length;
    const again = await scan(reg, { analysisCache });
    expect(again.errors).toEqual([]);
    expect(reg.requests.filter((u) => u.endsWith(".tgz")).length).toBe(before);
  });

  test("no lockfile is NOT_FOUND; too many packages is LIMIT_EXCEEDED", async () => {
    const reg = registry();
    await expect(scan(reg)).rejects.toSatisfy((e) => isDepwardError(e, "NOT_FOUND"));
    await lock(reg, { "fx-files": "1.0.0", "fx-net": "1.0.0" });
    await expect(scan(reg, { maxPackages: 1 })).rejects.toSatisfy((e) => isDepwardError(e, "LIMIT_EXCEEDED"));
  });

  test("an unsupported lockfile format is INVALID_LOCKFILE", async () => {
    await writeFile(join(dir, "bun.lockb"), new Uint8Array([0x23, 0x21, 0x2f, 0x75, 0x73, 0x72]));
    await expect(scan(registry())).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_LOCKFILE"));
  });
});
