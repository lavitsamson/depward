import type { GateOptions } from "@depward/gate";

/** Process exit codes. See `docs/specs/gate.md` §CLI. */
export const EXIT: { readonly allow: 0; readonly error: 1; readonly ask: 10; readonly deny: 20 } = {
  allow: 0,
  error: 1,
  ask: 10,
  deny: 20,
};

/** Output sinks and process context, injectable for tests. */
export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  /** Default `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
  /** Default `process.cwd()`. */
  cwd?: string;
  /** Whether stdout is a terminal (for color). Default `process.stdout.isTTY`. */
  isTTY?: boolean;
  /** Clock in ms, for timing output. Default `performance.now`. */
  now?: () => number;
  /** Overrides for the gate (registry client, data files, clock), for tests. */
  gate?: Partial<GateOptions>;
}

/** {@link Io} with defaults filled in. */
export interface Runtime extends Io {
  /** depward's own version, for reports. */
  version: string;
  env: Readonly<Record<string, string | undefined>>;
  cwd: string;
  now: () => number;
}

/** A command-line mistake: printed with the usage hint, exit code 1. */
export class UsageError extends Error {
  override readonly name: string = "UsageError";
}
