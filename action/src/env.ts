// The Actions runner interface: inputs, workflow commands, outputs, and the job summary.
// Written here instead of depending on @actions/core (CLAUDE.md: allowlisted runtime
// dependencies only). Docs, checked 2026-11-12:
// - inputs: https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax#inputs
//   (INPUT_<NAME>, upper-cased, spaces to `_`, hyphens kept)
// - commands, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY (1 MiB per step):
//   https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands

import { randomUUID } from "node:crypto";
import { appendFile } from "node:fs/promises";
import { DepwardError, escapeUnsafe } from "@depward/core";

/** Environment variables, as `process.env`. */
export type Env = Readonly<Record<string, string | undefined>>;

/** The raw value of an input, trimmed. Empty when unset. */
export function getInput(env: Env, name: string): string {
  return (env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();
}

/** A boolean input: `true` or `false` (any case). Empty gives `fallback`. */
export function getBooleanInput(env: Env, name: string, fallback: boolean): boolean {
  const v = getInput(env, name).toLowerCase();
  if (v === "") return fallback;
  if (v === "true") return true;
  if (v === "false") return false;
  throw new DepwardError("INVALID_ARGUMENT", `input ${name} must be true or false`);
}

// Workflow-command escaping as done by @actions/core (the docs page doesn't list it):
// data escapes % CR LF; property values also escape : and ,.
const escapeData = (s: string): string => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escapeProperty = (s: string): string => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

/** Where log lines go. */
export interface Log {
  info: (message: string) => void;
  /** An annotation: `level` is `notice`, `warning`, or `error`. */
  annotate: (level: "notice" | "warning" | "error", message: string, title?: string) => void;
}

/**
 * A {@link Log} that writes workflow commands to `write`. Messages may contain package
 * text, so controls are made visible first; that also stops a message from starting a
 * workflow command of its own on a new line.
 */
export function createLog(write: (line: string) => void): Log {
  return {
    info: (message) => {
      for (const line of message.split("\n")) write(line.startsWith("::") ? ` ${line}` : line);
    },
    annotate: (level, message, title) => {
      const props = title === undefined ? "" : ` title=${escapeProperty(escapeUnsafe(title, 200))}`;
      write(`::${level}${props}::${escapeData(escapeUnsafe(message, 2000))}`);
    },
  };
}

/** Appends `name=value` outputs to the `GITHUB_OUTPUT` file. A no-op when it's unset. */
export async function setOutputs(env: Env, outputs: Record<string, string>): Promise<void> {
  const file = env["GITHUB_OUTPUT"];
  if (file === undefined || file === "") return;
  let text = "";
  for (const [name, value] of Object.entries(outputs)) {
    if (!value.includes("\n")) text += `${name}=${value}\n`;
    else {
      const delimiter = `ghadelimiter_${randomUUID()}`;
      text += `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
    }
  }
  await appendFile(file, text, "utf8");
}

/** The job summary is capped at 1 MiB per step; leave room for other writers. */
export const SUMMARY_MAX_BYTES = 1_000_000;

/** Appends Markdown to the job summary. Returns false when `GITHUB_STEP_SUMMARY` is unset. */
export async function appendSummary(env: Env, markdown: string): Promise<boolean> {
  const file = env["GITHUB_STEP_SUMMARY"];
  if (file === undefined || file === "") return false;
  if (Buffer.byteLength(markdown, "utf8") > SUMMARY_MAX_BYTES) throw new DepwardError("LIMIT_EXCEEDED", "the report is larger than the job summary limit");
  await appendFile(file, `${markdown}\n`, "utf8");
  return true;
}
