// Claude Code PreToolUse hook adapter.
// Docs (read 2026-11-10): https://code.claude.com/docs/en/hooks
//   - stdin: { session_id, cwd, hook_event_name: "PreToolUse", tool_name: "Bash",
//     tool_input: { command, description?, timeout?, run_in_background? }, tool_use_id, … }
//   - stdout (exit 0): { hookSpecificOutput: { hookEventName: "PreToolUse",
//     permissionDecision: "allow" | "deny" | "ask" | "defer",
//     permissionDecisionReason, additionalContext? } }
//   - "allow" skips the user's permission prompt, so depward never sends it: a command
//     with nothing risky to install gets no output, and Claude Code's own permission
//     rules decide as if depward weren't there.
//   - The reason of "deny" is shown to Claude; the reason of "ask" is shown to the user,
//     so for "ask" it is also passed to Claude as additionalContext.
//   - Exit codes other than 0 and 2 let the tool call proceed, so the hook always exits
//     0 and expresses failures as a decision (onError).

import type { HookAdapter, HookParse, HookResponse, HookVerdict } from "./types.ts";

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parse(payload: unknown): HookParse {
  if (!isObject(payload)) return { kind: "invalid", problem: "the hook input is not a JSON object" };
  const event = payload["hook_event_name"];
  // Older payloads may omit the event name; anything else isn't ours.
  if (event !== undefined && event !== "PreToolUse") return { kind: "ignore" };
  if (payload["tool_name"] !== "Bash") return { kind: "ignore" };
  const input = payload["tool_input"];
  const command = isObject(input) ? input["command"] : undefined;
  if (typeof command !== "string") return { kind: "invalid", problem: "the Bash tool input has no command string" };
  const cwd = payload["cwd"];
  return { kind: "check", request: { command, ...(typeof cwd === "string" && cwd !== "" ? { cwd } : {}) } };
}

function respond(verdict: HookVerdict): HookResponse {
  if (verdict.action === "allow") return { stdout: "", exitCode: 0 };
  const output = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: verdict.action,
      permissionDecisionReason: verdict.reason,
      ...(verdict.action === "ask" ? { additionalContext: verdict.reason } : {}),
    },
  };
  return { stdout: `${JSON.stringify(output)}\n`, exitCode: 0 };
}

/** The Claude Code adapter: `PreToolUse` events for the `Bash` tool. */
export const claudeAdapter: HookAdapter = { name: "claude", parse, respond };
