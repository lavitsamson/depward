import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { describe, expect, test } from "vitest";
import { createLog, setOutputs } from "../src/env.ts";
import { API_VERSION, GitHubApiError, createGitHub } from "../src/github.ts";

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function fakeFetch(respond: (req: Seen) => { status: number; body?: unknown }): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const f = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const req: Seen = { url: String(url), method: init?.method ?? "GET", headers: init?.headers as Record<string, string>, body: init?.body === undefined ? undefined : JSON.parse(String(init.body)) };
    seen.push(req);
    const { status, body } = respond(req);
    return new Response(body === undefined ? null : JSON.stringify(body), { status });
  };
  return { fetch: f as typeof fetch, seen };
}

const page = (n: number, count: number): unknown[] => Array.from({ length: count }, (_, i) => ({ id: n * 1000 + i, body: "b", html_url: "u", user: { type: "Bot" } }));

describe("createGitHub", () => {
  test("lists comments across pages with the API headers", async () => {
    const { fetch, seen } = fakeFetch((r) => ({ status: 200, body: r.url.endsWith("page=1") ? page(1, 100) : page(2, 3) }));
    const gh = createGitHub({ token: "t", repository: "acme/app", fetch });
    const list = await gh.listComments(7);
    expect(list).toHaveLength(103);
    expect(seen.map((s) => s.url)).toEqual([
      "https://api.github.com/repos/acme/app/issues/7/comments?per_page=100&page=1",
      "https://api.github.com/repos/acme/app/issues/7/comments?per_page=100&page=2",
    ]);
    expect(seen[0]?.headers).toMatchObject({ authorization: "Bearer t", "x-github-api-version": API_VERSION, accept: "application/vnd.github+json" });
  });

  test("uploads SARIF gzipped and base64-encoded", async () => {
    const { fetch, seen } = fakeFetch(() => ({ status: 202, body: { id: "47" } }));
    const gh = createGitHub({ token: "t", repository: "acme/app", apiUrl: "https://ghe.example/api/v3/", fetch });
    expect(await gh.uploadSarif({ sarif: '{"version":"2.1.0"}', commitSha: "abc", ref: "refs/pull/7/merge", toolName: "depward" })).toBe("47");
    expect(seen[0]?.url).toBe("https://ghe.example/api/v3/repos/acme/app/code-scanning/sarifs");
    const body = seen[0]?.body as { sarif: string; commit_sha: string; ref: string };
    expect(gunzipSync(Buffer.from(body.sarif, "base64")).toString("utf8")).toBe('{"version":"2.1.0"}');
    expect(body).toMatchObject({ commit_sha: "abc", ref: "refs/pull/7/merge" });
  });

  test("an error status is a GitHubApiError with the status", async () => {
    const { fetch } = fakeFetch(() => ({ status: 403, body: { message: "Resource not accessible by integration" } }));
    const err = await createGitHub({ token: "t", repository: "acme/app", fetch }).createComment(7, "x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GitHubApiError);
    expect((err as GitHubApiError).status).toBe(403);
  });

  test("rejects a non-https API URL and a malformed repository", () => {
    expect(() => createGitHub({ token: "t", repository: "acme/app", apiUrl: "http://api.example" })).toThrow(/https/);
    expect(() => createGitHub({ token: "t", repository: "acme/app/../x" })).toThrow(/owner\/name/);
  });
});

describe("runner commands", () => {
  test("annotations escape newlines and controls; log lines can't start a command", () => {
    const out: string[] = [];
    const log = createLog((l) => out.push(l));
    log.annotate("warning", "a\nb%\u001b[31m", "t:i,t");
    log.info("ok\n::add-mask::secret");
    expect(out).toEqual(["::warning title=t%3Ai%2Ct::a\\x0ab%25\\x1b[31m", "ok", " ::add-mask::secret"]);
  });

  test("outputs: single-line and multiline values", async () => {
    const dir = await mkdtemp(join(tmpdir(), "depward-out-"));
    try {
      const file = join(dir, "out");
      await setOutputs({ GITHUB_OUTPUT: file }, { risk: "high", text: "a\nb" });
      expect(await readFile(file, "utf8")).toMatch(/^risk=high\ntext<<(ghadelimiter_[0-9a-f-]+)\na\nb\n\1\n$/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
