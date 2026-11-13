// Helpers shared by the `depward caps` subcommands.

import { readFile, rename, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { CAPS_LOCKFILE_NAME, DEFAULT_SCAN_CONCURRENCY, parseCapsLockfile, type CapsLockfile } from "@depward/caps";
import { UsageError } from "./runtime.ts";

/** Options every caps subcommand takes. */
export const COMMON_OPTIONS = {
  "caps-file": { type: "string" },
  concurrency: { type: "string" },
  config: { type: "string" },
  offline: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

/** Parses `--concurrency`. */
export function parseConcurrency(value: string | undefined): number {
  if (value === undefined) return DEFAULT_SCAN_CONCURRENCY;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 64) throw new UsageError("--concurrency must be an integer from 1 to 64");
  return n;
}

/** Validates `--caps-file`. */
export function parseCapsFile(value: string | undefined): string {
  const path = value ?? CAPS_LOCKFILE_NAME;
  if (path === "") throw new UsageError("--caps-file needs a path");
  return path;
}

/** The capability lockfile at `path`, or `null` when there is none. */
export async function readCapsFile(path: string): Promise<CapsLockfile | null> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  return parseCapsLockfile(text, basename(path));
}

/** Writes through a temporary file, so an interrupted write never leaves half a lockfile. */
export async function writeAtomic(path: string, text: string): Promise<void> {
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, text);
  await rename(tmp, path);
}

export const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

/** Network failures are often transient; the analysis cache makes a re-run cheap. */
export function retryHint(codes: readonly string[]): string {
  return codes.some((c) => c === "TIMEOUT" || c === "NETWORK")
    ? "depward: network failures are often transient. Analyzed packages are cached, so running the command again continues where this one stopped; a lower --concurrency helps with large tarballs\n"
    : "";
}
