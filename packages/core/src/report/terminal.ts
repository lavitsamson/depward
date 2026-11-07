// Human-readable terminal output. Color follows https://no-color.org and FORCE_COLOR.

import type { Finding, Severity } from "../findings.ts";
import { escapeUnsafe, evidenceLocation, packageLabel, sortFindings, summaryText } from "./common.ts";

/** Options for {@link renderTerminal}. */
export interface TerminalOptions {
  /** Emit ANSI colors. Decide with {@link colorEnabled}. Default `false`. */
  color?: boolean;
  /** Prefix of the summary line. Default `depward`. */
  title?: string;
}

/**
 * Whether to use color. `NO_COLOR` (any non-empty value) turns it off; `FORCE_COLOR`
 * turns it on (`0` or `false` turn it off); `TERM=dumb` turns it off; otherwise color is
 * used when the output is a TTY. Pure: pass `process.env` and `stream.isTTY`.
 */
export function colorEnabled(env: Readonly<Record<string, string | undefined>>, isTTY: boolean | undefined): boolean {
  if (env["NO_COLOR"]) return false;
  const force = env["FORCE_COLOR"];
  if (force !== undefined && force !== "") return force !== "0" && force.toLowerCase() !== "false";
  if (env["TERM"] === "dumb") return false;
  return isTTY === true;
}

const SGR: Record<Severity | "bold" | "dim", string> = {
  critical: "1;31",
  high: "31",
  medium: "33",
  low: "36",
  info: "90",
  bold: "1",
  dim: "2",
};

/**
 * Renders findings for a terminal, grouped in severity order. All package-controlled text
 * is escaped, so it cannot inject ANSI sequences, rewrite lines, or reorder text.
 */
export function renderTerminal(findings: readonly Finding[], opts: TerminalOptions = {}): string {
  const paint = (style: keyof typeof SGR, s: string): string => (opts.color ? `\u001b[${SGR[style]}m${s}\u001b[0m` : s);
  const lines = [`${opts.title ?? "depward"}: ${summaryText(findings)}`];
  for (const f of sortFindings(findings)) {
    lines.push("");
    lines.push(`${paint(f.severity, f.severity.toUpperCase().padEnd(8))}  ${paint("bold", escapeUnsafe(f.id, 80))}  ${escapeUnsafe(packageLabel(f))}`);
    lines.push(`  ${escapeUnsafe(f.message, 300)}`);
    for (const e of f.evidence) {
      const parts = [evidenceLocation(e), e.snippet === undefined ? undefined : `"${e.snippet}"`, e.detail];
      const text = parts.filter((p) => p !== undefined && p !== "").map((p) => escapeUnsafe(p ?? "")).join("  ");
      if (text) lines.push(paint("dim", `    - ${text}`));
    }
    lines.push(paint("dim", `  ${escapeUnsafe(f.docsUrl, 300)}`));
  }
  return `${lines.join("\n")}\n`;
}
