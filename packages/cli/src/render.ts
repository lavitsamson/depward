// Human-readable renderings of a gate Decision. Every package-controlled or
// user-supplied string goes through escapeUnsafe / escapeMarkdown before printing
// (CLAUDE.md: strip ANSI escapes and control characters).

import { escapeMarkdown, escapeUnsafe, renderMarkdown, renderTerminal, type PolicyAction } from "@depward/core";
import { decisionFindings, strictest, type Decision, type PackageDecision } from "@depward/gate";

const ACTION_SGR: Record<PolicyAction, string> = { deny: "1;31", ask: "1;33", allow: "32" };

/**
 * `name@version` (plus `(update from x)` on the update path), or `name@range` before
 * resolution, or the spec for non-registry sources.
 */
export function packageLabel(p: PackageDecision): string {
  if (p.version !== null) return p.update === null ? `${p.name}@${p.version}` : `${p.name}@${p.version} (update from ${p.update.from})`;
  return p.source === "registry" ? `${p.name}@${p.range}` : p.range;
}

function counts(decision: Decision): string {
  const n = decision.packages.length;
  if (n === 0) return "nothing to install";
  const by = (a: PolicyAction): number => decision.packages.filter((p) => p.action === a).length;
  const parts = (["deny", "ask", "allow"] as const).filter((a) => by(a) > 0).map((a) => `${by(a)} ${a}`);
  return `${n} package${n === 1 ? "" : "s"}: ${parts.join(", ")}`;
}

/** Options for {@link renderDecisionTerminal}. */
export interface TerminalDecisionOptions {
  color?: boolean;
  /** Also list findings the policy allows, as full finding blocks. */
  verbose?: boolean;
}

/**
 * The terminal view: a decision line, one block per package with the causes of a
 * non-allow action, and (verbose) the full finding report.
 */
export function renderDecisionTerminal(decision: Decision, opts: TerminalDecisionOptions = {}): string {
  const paint = (sgr: string, s: string): string => (opts.color ? `\u001b[${sgr}m${s}\u001b[0m` : s);
  const action = (a: PolicyAction): string => paint(ACTION_SGR[a], a.toUpperCase().padEnd(5));
  const lines = [`depward: ${paint(ACTION_SGR[decision.action], decision.action)} (${counts(decision)})`];
  let hidden = 0;

  const cause = (id: string, message: string): string => `         ${paint("1", escapeUnsafe(id, 80))}: ${escapeUnsafe(message, 300)}`;
  for (const p of decision.packages) {
    lines.push("", `  ${action(p.action)}  ${escapeUnsafe(packageLabel(p), 200)}`);
    if (p.update !== null) lines.push(`         diffed against ${escapeUnsafe(p.update.from, 100)} locked in ${escapeUnsafe(p.update.lockfile, 100)}`);
    if (p.listed !== null) lines.push(`         on the ${p.listed.list} list (${escapeUnsafe(JSON.stringify(p.listed.entry), 200)})`);
    for (const d of p.findings) {
      if (d.action === "allow") hidden++;
      else lines.push(cause(d.finding.id, d.finding.message));
    }
    if (p.errorAction !== null && p.errorAction !== "allow") {
      for (const e of p.errors) lines.push(cause(`lookup failed (${e.code})`, `${e.message}; onError is ${p.errorAction}`));
    }
  }
  const command = decision.findings.filter((d) => d.action !== "allow");
  hidden += decision.findings.length - command.length;
  if (command.length > 0) {
    lines.push("", `  ${action(strictest(command.map((d) => d.action)))}  (command)`);
    for (const d of command) lines.push(cause(d.finding.id, d.finding.message));
  }

  if (opts.verbose) {
    const all = decisionFindings(decision);
    if (all.length > 0) lines.push("", renderTerminal(all, { color: opts.color ?? false, title: "findings" }).trimEnd());
  } else if (hidden > 0) {
    lines.push("", `${hidden} finding${hidden === 1 ? "" : "s"} allowed by policy not shown (--verbose shows them).`);
  }
  return `${lines.join("\n")}\n`;
}

/** The Markdown view: a decision table, then the standard findings report. */
export function renderDecisionMarkdown(decision: Decision): string {
  const rows = decision.packages.map((p) => `| ${p.action} | <code>${escapeMarkdown(packageLabel(p))}</code> |`);
  const table = rows.length === 0 ? "" : `\n| Action | Package |\n|---|---|\n${rows.join("\n")}\n`;
  return `**depward: ${decision.action}** (${counts(decision)})\n${table}\n${renderMarkdown(decisionFindings(decision), { title: "depward findings" })}`;
}
