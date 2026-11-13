// The depward GitHub Action: diff the lockfile changes of a pull request (or push), keep
// one sticky PR comment up to date, upload SARIF, and fail the step at `fail-on`.
// Spec: docs/specs/diff.md § GitHub Action. Everything with side effects is injected,
// so tests run without a runner or network.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DepwardError, isDepwardError } from "@depward/core";
import { FAIL_ON_LEVELS, reachesFailOn, type FailOn } from "@depward/diff";
import { renderDiffMarkdown } from "../../packages/cli/src/diff-markdown.ts";
import type { DiffView } from "@depward/diff";
import { renderDiffSarif, renderDiffTerminal } from "../../packages/cli/src/diff-render.ts";
import { appendSummary, getBooleanInput, getInput, setOutputs, type Env, type Log } from "./env.ts";
import { GitHubApiError, upsertStickyComment, type GitHub } from "./github.ts";

/** First line of the sticky comment. Changing it orphans existing comments. */
export const COMMENT_MARKER = "<!-- depward-diff -->";

/** The Action's inputs, validated. */
export interface ActionInputs {
  failOn: FailOn;
  comment: boolean;
  sarif: boolean;
  /** Empty: derived from the event. */
  base: string;
  token: string;
}

/** Reads and validates the inputs declared in action.yml. */
export function readInputs(env: Env): ActionInputs {
  const failOn = getInput(env, "fail-on") || "critical";
  if (!(FAIL_ON_LEVELS as readonly string[]).includes(failOn)) throw new DepwardError("INVALID_ARGUMENT", `input fail-on must be one of ${FAIL_ON_LEVELS.join(", ")}`);
  return {
    failOn: failOn as FailOn,
    comment: getBooleanInput(env, "comment", true),
    sarif: getBooleanInput(env, "sarif", true),
    base: getInput(env, "base"),
    token: getInput(env, "github-token"),
  };
}

/** The parts of the workflow run the Action uses. */
export interface RunContext {
  eventName: string;
  /** The pull request number, for pull_request events. */
  pr: number | undefined;
  /** The PR comes from another repository: the token is read-only. */
  fromFork: boolean;
  /** The PR's base branch name. */
  baseRef: string | undefined;
  /** The commit before a push. */
  before: string | undefined;
  sha: string;
  ref: string;
}

const ZERO_SHA = /^0+$/;

/** Reads the run context from the environment and the event payload. */
export async function readContext(env: Env, readEvent: (path: string) => Promise<string> = (p) => readFile(p, "utf8")): Promise<RunContext> {
  const path = env["GITHUB_EVENT_PATH"];
  let event: Record<string, unknown> = {};
  if (path) {
    try {
      event = JSON.parse(await readEvent(path)) as Record<string, unknown>;
    } catch (err) {
      throw new DepwardError("INVALID_ARGUMENT", "cannot read the event payload", { cause: err });
    }
  }
  const pr = event["pull_request"] as { number?: unknown; head?: { repo?: { full_name?: unknown } | null }; base?: { ref?: unknown } } | undefined;
  const repo = env["GITHUB_REPOSITORY"] ?? "";
  const headRepo = pr?.head?.repo?.full_name;
  const before = typeof event["before"] === "string" && !ZERO_SHA.test(event["before"]) ? event["before"] : undefined;
  return {
    eventName: env["GITHUB_EVENT_NAME"] ?? "",
    pr: typeof pr?.number === "number" ? pr.number : undefined,
    // A deleted fork has no head repo; treat it as a fork too.
    fromFork: pr !== undefined && headRepo !== repo,
    baseRef: typeof pr?.base?.ref === "string" ? pr.base.ref : env["GITHUB_BASE_REF"] || undefined,
    before,
    sha: env["GITHUB_SHA"] ?? "",
    ref: env["GITHUB_REF"] ?? "",
  };
}

/** The git ref to compare with: the input, else the PR's base branch, else the commit before a push. */
export function resolveBase(inputs: ActionInputs, ctx: RunContext): string {
  if (inputs.base !== "") return inputs.base;
  if (ctx.pr !== undefined && ctx.baseRef !== undefined) return `origin/${ctx.baseRef}`;
  if (ctx.before !== undefined) return ctx.before;
  throw new DepwardError("INVALID_ARGUMENT", `cannot tell what to compare with (event: ${ctx.eventName || "none"}); set the base input`);
}

/** What {@link runAction} needs from the outside world. */
export interface ActionDeps {
  env: Env;
  log: Log;
  /** Runs the lockfile diff against `base` in the working directory. */
  computeView: (base: string) => Promise<DiffView>;
  /** Builds a GitHub client for the token. */
  github: (token: string) => GitHub;
  version: string;
  readEvent?: (path: string) => Promise<string>;
}

/** Runs the Action. Returns 0 when the step passes, 1 when it fails. */
export async function runAction(deps: ActionDeps): Promise<number> {
  const { env, log } = deps;
  const inputs = readInputs(env);
  const ctx = await readContext(env, deps.readEvent);
  const base = resolveBase(inputs, ctx);
  log.info(`depward diff: comparing the lockfiles with ${base} (fail-on ${inputs.failOn})`);

  const view = await deps.computeView(base);
  const tool = { name: "depward", version: deps.version };
  log.info(renderDiffTerminal(view, { color: false }));

  const markdown = renderDiffMarkdown(view, { marker: COMMENT_MARKER });
  const sarif = renderDiffSarif(view, tool);
  const outputs: Record<string, string> = { risk: view.risk, changes: String(view.packages.length) };
  const tmp = env["RUNNER_TEMP"];
  if (tmp) {
    const file = join(tmp, "depward-diff.sarif");
    await writeFile(file, sarif, "utf8");
    outputs["sarif-file"] = file;
  }

  const gh = inputs.token === "" ? undefined : deps.github(inputs.token);
  const readOnly = ctx.fromFork ? "the pull request comes from a fork, so the token is read-only" : undefined;

  // The sticky comment; the job summary when there is no PR or it can't be posted.
  let commented = false;
  if (inputs.comment && ctx.pr !== undefined) {
    if (readOnly !== undefined) log.annotate("notice", `Not commenting: ${readOnly}. The report is in the job summary.`, "depward");
    else if (gh === undefined) log.annotate("warning", "Not commenting: no github-token. The report is in the job summary.", "depward");
    else {
      try {
        const r = await upsertStickyComment(gh, ctx.pr, COMMENT_MARKER, markdown, { createIfMissing: view.packages.length > 0 });
        commented = r.action !== "skipped";
        if (r.action !== "skipped") {
          outputs["comment-url"] = r.url;
          log.info(`depward: ${r.action} the PR comment ${r.url}`);
        }
      } catch (err) {
        if (!(err instanceof GitHubApiError) || (err.status !== 403 && err.status !== 404)) throw err;
        log.annotate("warning", `Could not comment (HTTP ${err.status}); the job needs "permissions: pull-requests: write". The report is in the job summary.`, "depward");
      }
    }
  }
  if (!commented) await appendSummary(env, markdown);

  if (inputs.sarif) {
    if (readOnly !== undefined) log.annotate("notice", `Not uploading SARIF: ${readOnly}.`, "depward");
    else if (gh === undefined || ctx.sha === "" || ctx.ref === "") log.annotate("warning", "Not uploading SARIF: no github-token, GITHUB_SHA, or GITHUB_REF.", "depward");
    else {
      try {
        const id = await gh.uploadSarif({ sarif, commitSha: ctx.sha, ref: ctx.ref, toolName: "depward" });
        log.info(`depward: uploaded SARIF${id ? ` (${id})` : ""}`);
      } catch (err) {
        if (!(err instanceof GitHubApiError) || (err.status !== 403 && err.status !== 404)) throw err;
        log.annotate(
          "warning",
          `Could not upload SARIF (HTTP ${err.status}). Code scanning must be available for the repository, and the job needs "permissions: security-events: write".`,
          "depward",
        );
      }
    }
  }

  const failedLookups = view.packages.filter((p) => p.errors.length > 0).length;
  const reached = reachesFailOn(view.packages, inputs.failOn);
  outputs["failed"] = String(reached || failedLookups > 0);
  await setOutputs(env, outputs);

  if (reached) log.annotate("error", `Dependency risk ${view.risk} reaches fail-on ${inputs.failOn}.`, "depward");
  if (failedLookups > 0) log.annotate("error", `${failedLookups} package lookup${failedLookups === 1 ? "" : "s"} failed, so part of the change went unchecked.`, "depward");
  return reached || failedLookups > 0 ? 1 : 0;
}

/** Turns an unexpected error into a failed step with one error annotation. */
export function reportError(log: Log, err: unknown): number {
  const message = isDepwardError(err) ? `${err.code}: ${err.message}` : err instanceof Error ? err.message : "unknown error";
  log.annotate("error", message, "depward");
  return 1;
}
