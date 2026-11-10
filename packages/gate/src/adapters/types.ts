// Agent hook adapters: translate an agent's hook payload into a command to check,
// and a gate verdict into the agent's response format. Pure: no I/O.
// Spec: docs/specs/gate.md §Claude Code hook adapter.

import type { PolicyAction } from "@depward/core";

/** What a hook payload asks depward to check. */
export interface HookRequest {
  /** The shell command the agent is about to run. */
  readonly command: string;
  /** The agent's working directory, if the payload has one. */
  readonly cwd?: string;
}

/** The gate's answer, reduced to what a hook needs. */
export interface HookVerdict {
  readonly action: PolicyAction;
  /** Model-readable explanation. Empty for `allow`. */
  readonly reason: string;
}

/** What the hook process should write and exit with. */
export interface HookResponse {
  /** Written to stdout verbatim. `""` means no opinion. */
  readonly stdout: string;
  readonly exitCode: number;
}

/** The result of {@link HookAdapter.parse}. */
export type HookParse =
  | { readonly kind: "check"; readonly request: HookRequest }
  /** Not an event or tool depward handles: respond with no opinion. */
  | { readonly kind: "ignore" }
  /** A payload that should be ours but can't be read. */
  | { readonly kind: "invalid"; readonly problem: string };

/** One agent's hook protocol. */
export interface HookAdapter {
  /** The name used on the command line (`depward hook <name>`). */
  readonly name: string;
  /** Classifies a parsed stdin payload. */
  parse(payload: unknown): HookParse;
  /** Renders a verdict in the agent's format. */
  respond(verdict: HookVerdict): HookResponse;
}
