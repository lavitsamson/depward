// GitHub-flavored Markdown (PR comments, job summaries). Shape follows docs/specs/diff.md
// § Markdown report format. Everything package-controlled is escaped so it cannot add
// HTML, links, images, @-mentions, or break the table.

import type { Finding, Severity } from "../findings.ts";
import { compareSeverity } from "../findings.ts";
import { escapeUnsafe, evidenceLocation, packageLabel, sortFindings, summaryText } from "./common.ts";

/** Options for {@link renderMarkdown}. */
export interface MarkdownOptions {
  /** Heading prefix. Default `depward`. */
  title?: string;
  /** Packages whose worst finding is at least this severe start expanded. Default `high`. */
  expandAtLeast?: Severity;
}

const ICON: Record<Severity, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };

/**
 * Escapes untrusted text for Markdown and inline HTML: controls become visible escapes,
 * HTML special characters become entities, Markdown punctuation is backslash-escaped,
 * newlines become spaces, and `@` gets a zero-width space so it never mentions anyone.
 * Truncated to `max` characters (default 200).
 */
export function escapeMarkdown(s: string, max = 200): string {
  // Backslash escapes first, so the entities added next are not themselves escaped.
  // Escaping `[`/`]` is enough to stop links and images; `:` breaks bare autolinks.
  return escapeUnsafe(s, max)
    .replace(/[\\`*_[\]#|~:]/g, "\\$&")
    .replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
    .replaceAll("@", "@&#8203;");
}

/** Wraps escaped text in `<code>` (no autolinks, mentions, or emphasis). */
const code = (s: string, max?: number): string => `<code>${escapeMarkdown(s, max)}</code>`;

/** A docs link, only for https URLs; anything else is rendered as plain text. */
function docsLink(f: Finding): string {
  const label = code(f.id, 80);
  if (!/^https:\/\/[^\s<>"'()]+$/.test(f.docsUrl)) return label;
  return `<a href="${encodeURI(f.docsUrl).replace(/"/g, "%22")}">${label}</a>`;
}

/** Renders findings as a summary table plus one collapsible section per package. */
export function renderMarkdown(findings: readonly Finding[], opts: MarkdownOptions = {}): string {
  const title = escapeMarkdown(opts.title ?? "depward", 80);
  if (findings.length === 0) return `## ${title}: no findings\n`;
  const sorted = sortFindings(findings);
  const out = [`## ${title}: ${summaryText(findings)}`, "", "| Risk | Package | Finding | Why |", "|---|---|---|---|"];
  for (const f of sorted) {
    out.push(`| ${ICON[f.severity]} ${f.severity} | ${code(packageLabel(f))} | ${docsLink(f)} | ${escapeMarkdown(f.message, 300)} |`);
  }

  // Group by package label, in order of first appearance (that is, by worst severity).
  const groups = new Map<string, Finding[]>();
  for (const f of sorted) {
    const key = packageLabel(f);
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  const expandAt = opts.expandAtLeast ?? "high";
  for (const [label, list] of groups) {
    const worst = list[0]?.severity ?? "info";
    const open = compareSeverity(worst, expandAt) <= 0 ? " open" : "";
    out.push("", `<details${open}><summary>${ICON[worst]} ${code(label)}: ${list.length} finding${list.length === 1 ? "" : "s"}</summary>`, "");
    for (const f of list) {
      out.push(`- **${f.severity}** ${docsLink(f)}: ${escapeMarkdown(f.message, 300)}`);
      for (const e of f.evidence) {
        const loc = evidenceLocation(e);
        const parts = [loc === undefined ? undefined : code(loc), e.snippet === undefined ? undefined : code(e.snippet), e.detail === undefined ? undefined : escapeMarkdown(e.detail)];
        const line = parts.filter((p) => p !== undefined).join(" ");
        if (line) out.push(`  - ${line}`);
      }
    }
    out.push("", "</details>");
  }
  return `${out.join("\n")}\n`;
}
