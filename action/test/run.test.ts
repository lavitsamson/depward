import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, Severity } from "@depward/core";
import type { DiffView, PackageChangeResult } from "@depward/diff";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import type { Log } from "../src/env.ts";
import { GitHubApiError, type GitHub, type IssueComment } from "../src/github.ts";
import { COMMENT_MARKER, readInputs, resolveBase, runAction, type RunContext } from "../src/run.ts";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-action-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function finding(severity: Severity): Finding {
  return { id: "diff-new-install-script", severity, package: "foo", version: "1.0.1", message: "adds a postinstall script", evidence: [], docsUrl: "https://example.invalid/f" };
}

function view(risk: Severity | null): DiffView {
  const packages: PackageChangeResult[] =
    risk === null ? [] : [{ kind: "updated", name: "foo", from: "1.0.0", to: "1.0.1", lockfiles: ["package-lock.json"], line: 4, findings: [finding(risk)], errors: [], risk }];
  return { packages, findings: packages.flatMap((p) => p.findings), risk: risk ?? "info", lockfiles: [], skipped: [], base: "0123456789abcdef", head: null };
}

function check(status: number | undefined, what: string): void {
  if (status !== undefined) throw new GitHubApiError(status, `${what}: HTTP ${status}`);
}

/** An in-memory GitHub with a call log. */
function fakeGitHub(comments: IssueComment[] = [], fail: { comment?: number; sarif?: number } = {}): GitHub & { calls: string[]; comments: IssueComment[] } {
  const calls: string[] = [];
  return {
    calls,
    comments,
    async listComments(issue) {
      calls.push(`list ${issue}`);
      check(fail.comment, "list");
      return comments;
    },
    async createComment(issue, body) {
      calls.push(`create ${issue}`);
      const c = { id: 100 + comments.length, body, htmlUrl: `https://github.example/c/${100 + comments.length}`, userType: "Bot" };
      comments.push(c);
      return c;
    },
    async updateComment(id, body) {
      calls.push(`update ${id}`);
      const c = comments.find((x) => x.id === id);
      if (c === undefined) throw new GitHubApiError(404, "no comment");
      c.body = body;
      return c;
    },
    async uploadSarif({ commitSha, ref }) {
      calls.push(`sarif ${commitSha} ${ref}`);
      check(fail.sarif, "sarif");
      return "upload-1";
    },
  };
}

interface Harness {
  code: number;
  lines: string[];
  annotations: string[];
  outputs: string;
  summary: string;
  bases: string[];
}

async function run(opts: { event: Record<string, unknown>; eventName?: string; view?: DiffView; gh?: GitHub; inputs?: Record<string, string> }): Promise<Harness> {
  const eventPath = join(dir, "event.json");
  await writeFile(eventPath, JSON.stringify(opts.event));
  const outputFile = join(dir, "output");
  const summaryFile = join(dir, "summary");
  await writeFile(outputFile, "");
  await writeFile(summaryFile, "");
  const env: Record<string, string> = {
    GITHUB_EVENT_NAME: opts.eventName ?? "pull_request",
    GITHUB_EVENT_PATH: eventPath,
    GITHUB_REPOSITORY: "acme/app",
    GITHUB_SHA: "abc123",
    GITHUB_REF: "refs/pull/7/merge",
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    RUNNER_TEMP: dir,
    "INPUT_GITHUB-TOKEN": "t0ken",
    ...Object.fromEntries(Object.entries(opts.inputs ?? {}).map(([k, v]) => [`INPUT_${k.toUpperCase()}`, v])),
  };
  const lines: string[] = [];
  const annotations: string[] = [];
  const log: Log = { info: (m) => lines.push(m), annotate: (level, m) => annotations.push(`${level}: ${m}`) };
  const bases: string[] = [];
  const gh = opts.gh ?? fakeGitHub();
  const code = await runAction({
    env,
    log,
    version: "0.0.0",
    computeView: async (base) => {
      bases.push(base);
      return opts.view ?? view("high");
    },
    github: () => gh,
  });
  return { code, lines, annotations, outputs: await readFile(outputFile, "utf8"), summary: await readFile(summaryFile, "utf8"), bases };
}

const prEvent = (fork = false): Record<string, unknown> => ({
  pull_request: { number: 7, head: { repo: { full_name: fork ? "mallory/app" : "acme/app" } }, base: { ref: "main" } },
});

describe("runAction on a pull request", () => {
  test("creates the sticky comment, uploads SARIF, and passes below fail-on", async () => {
    const gh = fakeGitHub();
    const r = await run({ event: prEvent(), gh });
    expect(r.code).toBe(0);
    expect(r.bases).toEqual(["origin/main"]);
    expect(gh.calls).toEqual(["list 7", "create 7", "sarif abc123 refs/pull/7/merge"]);
    expect(gh.comments[0]?.body.startsWith(`${COMMENT_MARKER}\n## depward: 1 dependency change, 1 needs review`)).toBe(true);
    expect(r.outputs).toContain("risk=high\n");
    expect(r.outputs).toContain("failed=false\n");
    expect(r.outputs).toContain("comment-url=https://github.example/c/100\n");
    expect(r.summary).toBe("");
    expect(JSON.parse(await readFile(join(dir, "depward-diff.sarif"), "utf8")).runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(4);
  });

  test("updates the bot's comment and ignores a user's comment with the marker", async () => {
    const gh = fakeGitHub([
      { id: 1, body: `${COMMENT_MARKER}\nfake`, htmlUrl: "u1", userType: "User" },
      { id: 2, body: `${COMMENT_MARKER}\nold report`, htmlUrl: "u2", userType: "Bot" },
    ]);
    await run({ event: prEvent(), gh, inputs: { sarif: "false" } });
    expect(gh.calls).toEqual(["list 7", "update 2"]);
    expect(gh.comments[0]?.body).toBe(`${COMMENT_MARKER}\nfake`);
    expect(gh.comments[1]?.body).toContain("## depward:");
  });

  test("no dependency changes: no new comment, report in the job summary", async () => {
    const gh = fakeGitHub();
    const r = await run({ event: prEvent(), gh, view: view(null), inputs: { sarif: "false" } });
    expect(gh.calls).toEqual(["list 7"]);
    expect(r.summary).toContain("## depward: 0 dependency changes");
  });

  test("fail-on reached: the step fails with an error annotation", async () => {
    const r = await run({ event: prEvent(), view: view("critical") });
    expect(r.code).toBe(1);
    expect(r.outputs).toContain("failed=true\n");
    expect(r.annotations).toContain("error: Dependency risk critical reaches fail-on critical.");
  });

  test("a fork PR: no API writes, the report goes to the job summary", async () => {
    const gh = fakeGitHub();
    const r = await run({ event: prEvent(true), gh });
    expect(gh.calls).toEqual([]);
    expect(r.summary).toContain("## depward: 1 dependency change");
    expect(r.annotations.filter((a) => a.startsWith("notice:"))).toHaveLength(2);
    expect(r.code).toBe(0);
  });

  test("a read-only token (403) falls back to the summary and warns", async () => {
    const gh = fakeGitHub([], { comment: 403, sarif: 403 });
    const r = await run({ event: prEvent(), gh });
    expect(r.code).toBe(0);
    expect(r.summary).toContain("## depward:");
    expect(r.annotations.some((a) => a.includes("pull-requests: write"))).toBe(true);
    expect(r.annotations.some((a) => a.includes("security-events: write"))).toBe(true);
  });

  test("other API failures fail the step", async () => {
    await expect(run({ event: prEvent(), gh: fakeGitHub([], { comment: 500 }) })).rejects.toThrow(/HTTP 500/);
  });
});

const ctx = (over: Partial<RunContext>): RunContext => ({ eventName: "push", pr: undefined, fromFork: false, baseRef: undefined, before: undefined, sha: "s", ref: "r", ...over });
const inputs = (base = ""): ReturnType<typeof readInputs> => ({ failOn: "critical", comment: true, sarif: true, base, token: "" });

describe("inputs and base", () => {

  test("defaults, and validation", () => {
    expect(readInputs({})).toEqual({ failOn: "critical", comment: true, sarif: true, base: "", token: "" });
    expect(readInputs({ "INPUT_FAIL-ON": " high ", INPUT_COMMENT: "FALSE" })).toMatchObject({ failOn: "high", comment: false });
    expect(() => readInputs({ "INPUT_FAIL-ON": "severe" })).toThrow(/fail-on must be one of/);
    expect(() => readInputs({ INPUT_SARIF: "yes" })).toThrow(/sarif must be true or false/);
  });

  test("base: the input, else the PR base branch, else the commit before a push", () => {
    expect(resolveBase(inputs("origin/release"), ctx({ pr: 1, baseRef: "main" }))).toBe("origin/release");
    expect(resolveBase(inputs(), ctx({ pr: 1, baseRef: "main" }))).toBe("origin/main");
    expect(resolveBase(inputs(), ctx({ before: "deadbeef" }))).toBe("deadbeef");
    expect(() => resolveBase(inputs(), ctx({ eventName: "workflow_dispatch" }))).toThrow(/set the base input/);
  });

  test("a push that created the branch (zero before) needs the base input", async () => {
    await expect(run({ event: { before: "0000000000000000000000000000000000000000" }, eventName: "push" })).rejects.toThrow(/set the base input/);
  });
});
