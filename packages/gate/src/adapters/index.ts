// Hook adapters and the reason text they share.

import type { Decision } from "../gate.ts";
import { claudeAdapter } from "./claude.ts";
import type { HookAdapter, HookVerdict } from "./types.ts";

export { claudeAdapter } from "./claude.ts";
export type { HookAdapter, HookParse, HookRequest, HookResponse, HookVerdict } from "./types.ts";

/** Every adapter, by command-line name. */
export const HOOK_ADAPTERS: Readonly<Record<string, HookAdapter>> = { claude: claudeAdapter };

const MAX_REASONS = 5;
const MAX_REASON_CHARS = 2000;

/**
 * Reduces a decision to a hook verdict with a concise, model-readable reason: up to five
 * causes (deny first), each naming the package, the finding, and its message, which
 * carries the suggested real name or older version when there is one.
 */
export function hookVerdict(decision: Decision): HookVerdict {
  if (decision.action === "allow") return { action: "allow", reason: "" };
  const shown = decision.reasons.slice(0, MAX_REASONS).map((r) => `depward: ${r}`);
  const more = decision.reasons.length - shown.length;
  if (more > 0) shown.push(`depward: (+${more} more; run \`depward check --command …\` for the full report)`);
  if (decision.action === "deny") {
    shown.push("Don't work around this check. Use the suggested package or version if there is one, or ask the user.");
  }
  let reason = shown.join("\n");
  if (reason.length > MAX_REASON_CHARS) reason = `${reason.slice(0, MAX_REASON_CHARS - 1)}…`;
  return { action: decision.action, reason };
}
