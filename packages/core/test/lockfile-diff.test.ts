import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { diffLockfiles, filesAtRef, isDepwardError, mergeBase, parseLockfile, readFileAtRef } from "../src/index.ts";

const npmLock = (packages: Record<string, Record<string, unknown>>): string =>
  JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "root" }, ...packages } });

const keys = (xs: { name: string; version: string }[]): string[] => xs.map((e) => `${e.name}@${e.version}`);

describe("diffLockfiles", () => {
  test("reports added, removed, and changed entries, sorted by key", () => {
    const base = parseLockfile(
      "package-lock.json",
      npmLock({
        "node_modules/keep": { version: "1.0.0", integrity: "sha512-K", resolved: "https://r.example.com/keep-1.0.0.tgz" },
        "node_modules/bump": { version: "1.0.0", integrity: "sha512-B1" },
        "node_modules/gone": { version: "1.0.0", integrity: "sha512-G" },
        "node_modules/swap": { version: "1.0.0", integrity: "sha512-S1" },
        "node_modules/move": { version: "1.0.0", integrity: "sha512-M", dev: true },
      }),
    );
    const head = parseLockfile(
      "package-lock.json",
      npmLock({
        "node_modules/keep": { version: "1.0.0", integrity: "sha512-K", resolved: "https://r.example.com/keep-1.0.0.tgz" },
        "node_modules/bump": { version: "1.1.0", integrity: "sha512-B2" },
        "node_modules/swap": { version: "1.0.0", integrity: "sha512-S2" },
        "node_modules/move": { version: "1.0.0", integrity: "sha512-M" },
        "node_modules/zz-new": { version: "0.1.0", integrity: "sha512-N" },
        "node_modules/aa-new": { version: "0.1.0", integrity: "sha512-A" },
      }),
    );
    const diff = diffLockfiles(base, head);
    expect(keys(diff.added)).toEqual(["aa-new@0.1.0", "bump@1.1.0", "zz-new@0.1.0"]);
    expect(keys(diff.removed)).toEqual(["bump@1.0.0", "gone@1.0.0"]);
    expect(diff.changed.map((c) => [`${c.before.name}@${c.before.version}`, c.before.integrity, c.after.integrity, c.after.dev])).toEqual([
      ["move@1.0.0", "sha512-M", "sha512-M", false],
      ["swap@1.0.0", "sha512-S1", "sha512-S2", false],
    ]);
  });

  test("an identical lockfile has an empty diff", () => {
    const text = npmLock({ "node_modules/a": { version: "1.0.0", integrity: "sha512-A" } });
    expect(diffLockfiles(parseLockfile("package-lock.json", text), parseLockfile("package-lock.json", text))).toEqual({
      added: [],
      removed: [],
      changed: [],
    });
  });

  test("a missing integrity on one side is not a change, but a different source is", () => {
    const yarnRegistry = parseLockfile("yarn.lock", '# yarn lockfile v1\n\na@^1:\n  version "1.0.0"\n  resolved "https://r.example.com/a/-/a-1.0.0.tgz"\n');
    const yarnGit = parseLockfile("yarn.lock", '# yarn lockfile v1\n\n"a@github:x/a":\n  version "1.0.0"\n  resolved "https://codeload.github.com/x/a/tar.gz/abc"\n');
    const npm = parseLockfile("package-lock.json", npmLock({ "node_modules/a": { version: "1.0.0", integrity: "sha512-A", resolved: "https://r.example.com/a/-/a-1.0.0.tgz" } }));
    expect(yarnRegistry.entries.get("a@1.0.0")?.integrity).toBeNull();
    expect(diffLockfiles(yarnRegistry, npm).changed).toEqual([]);
    expect(diffLockfiles(yarnGit, npm).changed.map((c) => [c.before.source, c.after.source])).toEqual([["git", "registry"]]);
  });
});

describe("readFileAtRef", () => {
  let repo: string;
  const git = (...args: string[]): string =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args], {
      cwd: repo,
      encoding: "utf8",
    });

  beforeAll(async () => {
    repo = await mkdtemp(join(tmpdir(), "depward-git-"));
    git("init", "-q", "-b", "main");
    await mkdir(join(repo, "sub"));
    await writeFile(join(repo, "sub", "package-lock.json"), "v1\n");
    git("add", ".");
    git("commit", "-q", "-m", "one");
    await writeFile(join(repo, "sub", "package-lock.json"), "v2\n");
    git("commit", "-q", "-am", "two");
  });
  afterAll(async () => rm(repo, { recursive: true, force: true }));

  test("reads a file at a ref, relative to cwd", async () => {
    expect(await readFileAtRef("HEAD~1", "sub/package-lock.json", repo)).toBe("v1\n");
    expect(await readFileAtRef("main", "package-lock.json", join(repo, "sub"))).toBe("v2\n");
    expect(await readFileAtRef("HEAD", "sub\\package-lock.json", repo)).toBe("v2\n");
  });

  test("returns null when the file does not exist at that ref", async () => {
    expect(await readFileAtRef("HEAD", "missing.json", repo)).toBeNull();
  });

  test("throws for an unknown ref, and refuses option-like or odd refs", async () => {
    for (const ref of ["no-such-branch", "--output=/tmp/x", "-p", "a b", "HEAD:x", ""]) {
      await expect(readFileAtRef(ref, "sub/package-lock.json", repo), ref).rejects.toSatisfy(
        (e) => isDepwardError(e, "INVALID_ARGUMENT") || isDepwardError(e, "GIT"),
      );
    }
  });

  test("mergeBase finds the common ancestor of HEAD and a ref", async () => {
    const one = git("rev-parse", "HEAD~1").trim();
    git("checkout", "-q", "-b", "side", "HEAD~1");
    await writeFile(join(repo, "side.txt"), "s\n");
    git("add", ".");
    git("commit", "-q", "-m", "side");
    try {
      expect(await mergeBase("main", repo)).toBe(one);
      expect(await mergeBase("HEAD", repo)).toBe(git("rev-parse", "HEAD").trim());
    } finally {
      git("checkout", "-q", "main");
    }
    for (const ref of ["no-such-branch", "--all", "a b"]) {
      await expect(mergeBase(ref, repo), ref).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_ARGUMENT") || isDepwardError(e, "GIT"));
    }
  });

  test("filesAtRef lists which candidates exist at a ref, relative to cwd", async () => {
    expect(await filesAtRef("HEAD", ["sub/package-lock.json", "yarn.lock", "sub"], repo)).toEqual(["sub/package-lock.json"]);
    expect(await filesAtRef("HEAD~1", ["package-lock.json", "pnpm-lock.yaml"], join(repo, "sub"))).toEqual(["package-lock.json"]);
    expect(await filesAtRef("HEAD", [], repo)).toEqual([]);
    await expect(filesAtRef("--all", ["x"], repo)).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_ARGUMENT"));
    await expect(filesAtRef("no-such-branch", ["x"], repo)).rejects.toSatisfy((e) => isDepwardError(e, "GIT"));
  });

  test("throws GIT outside a repository", async () => {
    const dir = await mkdtemp(join(tmpdir(), "depward-nogit-"));
    try {
      await expect(readFileAtRef("HEAD", "x", dir)).rejects.toSatisfy((e) => isDepwardError(e, "GIT"));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
