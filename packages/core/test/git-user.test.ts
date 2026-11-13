import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { gitUserName } from "../src/index.ts";

describe("gitUserName", () => {
  let dir: string;
  const saved = { global: process.env["GIT_CONFIG_GLOBAL"], nosystem: process.env["GIT_CONFIG_NOSYSTEM"] };

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "depward-git-user-"));
    // Hide the machine's own git identity so the "unset" case is deterministic.
    const empty = join(dir, "empty.gitconfig");
    await writeFile(empty, "");
    process.env["GIT_CONFIG_GLOBAL"] = empty;
    process.env["GIT_CONFIG_NOSYSTEM"] = "1";
  });
  afterAll(async () => {
    for (const [key, value] of [["GIT_CONFIG_GLOBAL", saved.global], ["GIT_CONFIG_NOSYSTEM", saved.nosystem]] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(dir, { recursive: true, force: true });
  });

  test("null when user.name is unset", async () => {
    expect(await gitUserName(dir)).toBeNull();
  });

  test("reads the repository's user.name", async () => {
    const repo = join(dir, "repo");
    execFileSync("git", ["init", "-q", repo]);
    execFileSync("git", ["-C", repo, "config", "user.name", "Test Person"]);
    expect(await gitUserName(repo)).toBe("Test Person");
  });
});
