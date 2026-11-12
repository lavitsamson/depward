// The few GitHub REST calls the Action makes, over global fetch (CLAUDE.md: no HTTP
// client). Docs, checked 2026-11-12:
// - issue comments: https://docs.github.com/en/rest/issues/comments
// - SARIF upload: https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data
//   (gzip, then base64; 202 Accepted; 403 when code scanning isn't available)

import { promisify } from "node:util";
import { gzip as gzipCb } from "node:zlib";
import { DepwardError } from "@depward/core";

const gzip = promisify(gzipCb);

/** REST API version sent with every request. */
export const API_VERSION = "2026-03-10";
/** Per-request timeout. */
export const REQUEST_TIMEOUT_MS = 15_000;
/** Comment pages read when looking for the sticky comment (100 per page). */
export const MAX_COMMENT_PAGES = 10;

/** A non-2xx response. `status` tells a missing permission (403) from other failures. */
export class GitHubApiError extends DepwardError {
  override readonly name: string = "GitHubApiError";
  readonly status: number;

  constructor(status: number, message: string) {
    super("NETWORK", message);
    this.status = status;
  }
}

/** Options for {@link createGitHub}. */
export interface GitHubOptions {
  token: string;
  /** `owner/name`. */
  repository: string;
  /** Default `https://api.github.com` (GITHUB_API_URL on GitHub Enterprise). */
  apiUrl?: string;
  fetch?: typeof globalThis.fetch;
}

/** An issue comment, as far as the Action needs it. */
export interface IssueComment {
  id: number;
  body: string;
  htmlUrl: string;
  /** `Bot` for github-actions[bot] and other apps. */
  userType: string;
}

/** The calls the Action makes. */
export interface GitHub {
  listComments(issue: number): Promise<IssueComment[]>;
  createComment(issue: number, body: string): Promise<IssueComment>;
  updateComment(id: number, body: string): Promise<IssueComment>;
  /** Uploads a SARIF log; returns the upload id. */
  uploadSarif(input: { sarif: string; commitSha: string; ref: string; toolName: string }): Promise<string>;
}

const toComment = (raw: unknown): IssueComment => {
  const c = raw as { id?: unknown; body?: unknown; html_url?: unknown; user?: { type?: unknown } | null };
  if (typeof c.id !== "number") throw new DepwardError("INVALID_RESPONSE", "comment without an id");
  return { id: c.id, body: typeof c.body === "string" ? c.body : "", htmlUrl: typeof c.html_url === "string" ? c.html_url : "", userType: typeof c.user?.type === "string" ? c.user.type : "" };
};

/** A {@link GitHub} over the REST API. */
export function createGitHub(opts: GitHubOptions): GitHub {
  const apiUrl = (opts.apiUrl ?? "https://api.github.com").replace(/\/+$/, "");
  if (!/^https:\/\/[^\s/]+/.test(apiUrl)) throw new DepwardError("INVALID_ARGUMENT", "the GitHub API URL must use https");
  if (!/^[\w.-]+\/[\w.-]+$/.test(opts.repository)) throw new DepwardError("INVALID_ARGUMENT", "GITHUB_REPOSITORY must be owner/name");
  const doFetch = opts.fetch ?? globalThis.fetch;

  async function call(method: string, path: string, body?: unknown): Promise<unknown> {
    let res: Response;
    try {
      res = await doFetch(`${apiUrl}/repos/${opts.repository}${path}`, {
        method,
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${opts.token}`,
          "x-github-api-version": API_VERSION,
          "user-agent": "depward-action",
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      const timeout = err instanceof Error && err.name === "TimeoutError";
      throw new DepwardError(timeout ? "TIMEOUT" : "NETWORK", `${method} ${path} ${timeout ? "timed out" : "failed"}`, { cause: err });
    }
    if (!res.ok) {
      // The message is GitHub's, not package data, but keep it short.
      const detail = await res.text().then((t) => t.slice(0, 300), () => "");
      throw new GitHubApiError(res.status, `${method} ${path}: HTTP ${res.status} ${detail}`.trim());
    }
    return res.status === 204 ? null : res.json();
  }

  return {
    async listComments(issue) {
      const out: IssueComment[] = [];
      for (let page = 1; page <= MAX_COMMENT_PAGES; page++) {
        const list = await call("GET", `/issues/${issue}/comments?per_page=100&page=${page}`);
        if (!Array.isArray(list)) throw new DepwardError("INVALID_RESPONSE", "comment list is not an array");
        out.push(...list.map(toComment));
        if (list.length < 100) break;
      }
      return out;
    },
    createComment: async (issue, body) => toComment(await call("POST", `/issues/${issue}/comments`, { body })),
    updateComment: async (id, body) => toComment(await call("PATCH", `/issues/comments/${id}`, { body })),
    async uploadSarif({ sarif, commitSha, ref, toolName }) {
      const encoded = (await gzip(Buffer.from(sarif, "utf8"))).toString("base64");
      const res = (await call("POST", "/code-scanning/sarifs", { commit_sha: commitSha, ref, sarif: encoded, tool_name: toolName })) as { id?: unknown } | null;
      return typeof res?.id === "string" ? res.id : "";
    },
  };
}

/** What {@link upsertStickyComment} did. */
export type StickyResult = { action: "created" | "updated"; url: string } | { action: "skipped" };

/**
 * Updates the bot comment whose body starts with `marker`, or creates one. Only
 * comments by a bot account are considered, so a user who pastes the marker can't make
 * the Action edit their comment. With `createIfMissing: false` (nothing to report),
 * an existing comment is still updated but no new one is posted.
 */
export async function upsertStickyComment(gh: GitHub, issue: number, marker: string, body: string, opts: { createIfMissing: boolean }): Promise<StickyResult> {
  const existing = (await gh.listComments(issue)).find((c) => c.userType === "Bot" && c.body.startsWith(marker));
  if (existing !== undefined) {
    const updated = await gh.updateComment(existing.id, body);
    return { action: "updated", url: updated.htmlUrl };
  }
  if (!opts.createIfMissing) return { action: "skipped" };
  const created = await gh.createComment(issue, body);
  return { action: "created", url: created.htmlUrl };
}
