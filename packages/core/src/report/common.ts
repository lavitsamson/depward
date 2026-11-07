// Shared helpers for reporters: deterministic ordering, severity counts, and escaping of
// untrusted text (package names, messages, evidence). Pure.

import { compareFindings, SEVERITIES, type Finding, type Severity } from "../findings.ts";

/** Identifies the tool in JSON and SARIF output. */
export interface ToolInfo {
  /** Default `depward`. */
  name?: string;
  version?: string;
}

const cmp = (a: string | undefined, b: string | undefined): number => ((a ?? "") < (b ?? "") ? -1 : (a ?? "") > (b ?? "") ? 1 : 0);

/**
 * Sorts findings by severity, package, and id (as {@link compareFindings}), breaking ties
 * by version, message, and first evidence location, so output never depends on input order.
 */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return findings.toSorted(
    (a, b) =>
      compareFindings(a, b) ||
      cmp(a.version, b.version) ||
      cmp(a.message, b.message) ||
      cmp(a.evidence[0]?.file, b.evidence[0]?.file) ||
      (a.evidence[0]?.line ?? 0) - (b.evidence[0]?.line ?? 0),
  );
}

/** Number of findings per severity. Every severity is present. */
export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

/** `3 findings (1 critical, 2 high)`, or `no findings`. */
export function summaryText(findings: readonly Finding[]): string {
  if (findings.length === 0) return "no findings";
  const counts = countBySeverity(findings);
  const parts = SEVERITIES.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  return `${findings.length} finding${findings.length === 1 ? "" : "s"} (${parts.join(", ")})`;
}

// Characters that can hide or rewrite output: C0/C1 controls (including ESC, so ANSI
// sequences), zero-width and directional marks, bidi embeddings/overrides/isolates
// ("Trojan Source"), line/paragraph separators, and the BOM. The pattern is built from
// code points so the source stays readable.
const UNSAFE_RANGES: [number, number][] = [
  [0x00, 0x1f], [0x7f, 0x9f], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff, 0xfeff],
];
const hex4 = (n: number): string => `\\u${n.toString(16).padStart(4, "0")}`;
const UNSAFE = new RegExp(`[${UNSAFE_RANGES.map(([a, b]) => (a === b ? hex4(a) : `${hex4(a)}-${hex4(b)}`)).join("")}]`, "gu");

/**
 * Makes untrusted text safe to print: every unsafe character becomes a visible escape
 * (`\x1b`, `‮`), so tampering shows instead of taking effect. Then truncates to `max`
 * code points with an ellipsis.
 */
export function escapeUnsafe(s: string, max = 200): string {
  const escaped = s.replace(UNSAFE, (c) => {
    const code = c.codePointAt(0) ?? 0;
    return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : hex4(code);
  });
  const chars = [...escaped];
  return chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : escaped;
}

/** `file:line`, `file`, or `undefined`. */
export function evidenceLocation(e: Finding["evidence"][number]): string | undefined {
  if (e.file === undefined) return undefined;
  return e.line !== undefined && e.line > 0 ? `${e.file}:${e.line}` : e.file;
}

/** `name@version`, or just `name`. */
export function packageLabel(f: Pick<Finding, "package" | "version">): string {
  return f.version ? `${f.package}@${f.version}` : f.package;
}
