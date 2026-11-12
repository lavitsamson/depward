// The `depward diff --format markdown` report: a PR comment or job summary.
// Shape: docs/specs/diff.md § Markdown report format. Every package-controlled string
// (names, versions, messages, evidence) goes through escapeMarkdown, so it cannot add
// HTML, links, images, or @-mentions, or break the table. Snippets are capped at 200
// characters before escaping.

import { compareSeverity, escapeMarkdown, type Finding, type Severity } from "@depward/core";
import type { PackageChangeResult } from "@depward/diff";
import type { DiffView } from "./diff-render.ts";

/** Options for {@link renderDiffMarkdown}. */
export interface DiffMarkdownOptions {
  /**
   * Maximum length of the output in UTF-16 code units. Sections that don't fit are
   * dropped, most severe kept, with a note. Default 60,000 (a GitHub comment body is
   * capped at 65,536 characters).
   */
  maxLength?: number;
  /** Evidence items shown per finding. Default 5. */
  maxEvidence?: number;
}

/** The default {@link DiffMarkdownOptions.maxLength}. */
export const MARKDOWN_MAX_LENGTH = 60_000;

const ICON: Record<Severity, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };

// Short labels for the "Why" column. Other IDs are shown as they are.
const LABEL: Record<string, string> = {
  "diff-new-install-script": "new install script",
  "diff-new-capability": "new capability",
  "diff-new-network-in-non-network-pkg": "new network",
  "diff-new-sensitive-env": "new secret read",
  "diff-new-endpoint": "new endpoint",
  "diff-new-obfuscation": "new obfuscation",
  "diff-new-dependency": "new dependency",
  "diff-publisher-changed": "publisher changed",
  "diff-provenance-dropped": "provenance dropped",
  "diff-semver-mismatch": "semver mismatch",
  "lockfile-integrity-mismatch": "integrity mismatch",
  "non-registry-source": "non-registry source",
  denylisted: "deny-listed",
};

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const code = (s: string, max?: number): string => `<code>${escapeMarkdown(s, max)}</code>`;

/** A docs link, only for https URLs; anything else is plain text. */
function docsLink(f: Finding): string {
  const label = code(f.id, 80);
  if (!/^https:\/\/[^\s<>"'()]+$/.test(f.docsUrl)) return label;
  return `<a href="${encodeURI(f.docsUrl).replace(/"/g, "%22")}">${label}</a>`;
}

function changeText(p: PackageChangeResult): string {
  if (p.from !== undefined) return `${escapeMarkdown(p.from, 60)} → ${escapeMarkdown(p.to, 60)}`;
  return `${p.kind} ${escapeMarkdown(p.to, 100)}`;
}

/** Whether the package gets its own row and section (the rest are listed, collapsed). */
const flagged = (p: PackageChangeResult): boolean =>
  p.findings.some((f) => f.severity !== "info") || p.errors.length > 0 || p.listed?.list === "deny";

function why(p: PackageChangeResult): string {
  const labels = [...new Set(p.findings.filter((f) => f.severity !== "info").map((f) => LABEL[f.id] ?? f.id))];
  if (p.listed?.list === "deny" && !labels.includes("deny-listed")) labels.unshift("deny-listed");
  if (p.errors.length > 0) labels.push("lookup failed");
  const shown = labels.slice(0, 4).map((l) => escapeMarkdown(l, 60));
  return labels.length > 4 ? `${shown.join(" · ")} · +${labels.length - 4} more` : shown.join(" · ");
}

function findingLines(f: Finding, maxEvidence: number, allowed: boolean): string[] {
  const out = [`- **${allowed ? "allowed" : f.severity}** ${docsLink(f)}: ${escapeMarkdown(f.message, 300)}`];
  for (const e of f.evidence.slice(0, maxEvidence)) {
    const loc = e.file === undefined ? undefined : e.line !== undefined && e.line > 0 ? `${e.file}:${e.line}` : e.file;
    const parts = [loc === undefined ? undefined : code(loc, 200), e.snippet === undefined ? undefined : code(e.snippet, 200), e.detail === undefined ? undefined : escapeMarkdown(e.detail, 200)];
    const line = parts.filter((x) => x !== undefined).join(" ");
    if (line) out.push(`  - ${line}`);
  }
  if (f.evidence.length > maxEvidence) out.push(`  - _and ${f.evidence.length - maxEvidence} more_`);
  return out;
}

/** One collapsible section. High and critical start open; lower risks start collapsed. */
function packageSection(p: PackageChangeResult, maxEvidence: number): string {
  const open = compareSeverity(p.risk, "high") <= 0 ? " open" : "";
  const label = p.from === undefined ? `${p.name}@${p.to}` : `${p.name} ${p.from} → ${p.to}`;
  const out = [`<details${open}><summary>${ICON[p.risk]} <b>${p.risk}</b> · ${code(label, 240)} (${p.kind})</summary>`, ""];
  if (p.lockfiles.length > 0) out.push(`In ${p.lockfiles.map((l) => code(l, 200)).join(", ")}${p.line === undefined ? "" : ` (line ${p.line})`}.`, "");
  if (p.listed) out.push(`On the config's **${p.listed.list}** list.`, "");
  for (const f of p.findings) out.push(...findingLines(f, maxEvidence, false));
  for (const e of p.errors) out.push(`- **lookup failed** ${code(e.code, 40)}: ${escapeMarkdown(e.message, 300)}`);
  const allowed = p.allowedFindings ?? [];
  if (allowed.length > 0) {
    out.push("", `Allowed by the project config (not counted):`, "");
    for (const f of allowed) out.push(...findingLines(f, maxEvidence, true));
  }
  out.push("", "</details>");
  return out.join("\n");
}

function quietSection(packages: readonly PackageChangeResult[]): string {
  const items = packages.map((p) => {
    const allowed = p.allowedFindings?.length ?? 0;
    return `- ${code(p.name, 214)} ${changeText(p)}${allowed === 0 ? "" : ` · ${plural(allowed, "allowed finding")}`}`;
  });
  return [`<details><summary>${plural(packages.length, "package change")} with no findings</summary>`, "", ...items, "", "</details>"].join("\n");
}

/**
 * Renders a diff as GitHub-flavored Markdown: a heading, a summary table of packages
 * with findings, one collapsible section per such package (evidence with file:line and
 * snippets), then collapsed lists of quiet and skipped packages. Output fits in
 * `maxLength`; sections that don't fit are dropped with a note.
 */
export function renderDiffMarkdown(view: DiffView, opts: DiffMarkdownOptions = {}): string {
  const maxLength = opts.maxLength ?? MARKDOWN_MAX_LENGTH;
  const maxEvidence = opts.maxEvidence ?? 5;
  const n = view.packages.length;
  const shown = view.packages.filter(flagged);
  const quiet = view.packages.filter((p) => !flagged(p));
  const review = view.packages.filter((p) => compareSeverity(p.risk, "medium") <= 0 || p.errors.length > 0);
  const heading = `## depward: ${plural(n, "dependency change")}${review.length > 0 ? `, ${review.length} need${review.length === 1 ? "s" : ""} review` : ""}`;

  const head: string[] = [heading, ""];
  if (view.base !== null) {
    const target = view.head === null ? "the working tree" : code(view.head, 100);
    head.push(`Compared with ${code(view.base.slice(0, 12), 12)} (merge-base) → ${target}.`, "");
  }
  const notes = view.lockfiles.flatMap((l) => l.findings.map((f) => `- ${ICON[f.severity]} ${code(l.path, 200)}: ${escapeMarkdown(f.message, 300)}`));
  if (notes.length > 0) head.push(...notes, "");
  if (n === 0) return `${head.join("\n").trimEnd()}\n`;
  if (shown.length === 0) head.push("No findings.", "");

  // Blocks in priority order: table rows (worst first), sections, then the quiet lists.
  const rows = shown.map((p) => `| ${ICON[p.risk]} ${p.risk} | ${code(p.name, 214)} | ${changeText(p)} | ${why(p)} |`);
  const sections = shown.map((p) => packageSection(p, maxEvidence));
  const allowedCount = view.packages.reduce((sum, p) => sum + (p.allowedFindings?.length ?? 0), 0);
  const tail: string[] = [];
  if (allowedCount > 0) tail.push(`_${allowedCount === 1 ? "1 finding is" : `${allowedCount} findings are`} allowed by the project config and not counted._`);
  if (quiet.length > 0) tail.push(quietSection(quiet));
  if (view.skipped.length > 0) {
    const items = view.skipped.map((s) => `- ${code(s, 214)}`);
    tail.push([`<details><summary>${plural(view.skipped.length, "entry")} skipped (local or bundled)</summary>`, "", ...items, "", "</details>"].join("\n"));
  }

  const note = (rowCount: number, blocks: number): string =>
    `> [!NOTE]\n> The report did not fit in one comment: ${plural(rowCount, "table row")} and ${plural(blocks, "package section")} left out. Run \`depward diff --lockfile\` locally, or see the SARIF or JSON output, for the full report.`;
  const budget = maxLength - note(99_999, 99_999).length - 2;
  const out = [...head];
  let size = head.join("\n").length + 1;

  // The table takes at most half the budget, so the worst packages' evidence still fits.
  let droppedRows = 0;
  if (rows.length > 0) {
    const table = ["| Risk | Package | Change | Why |", "|---|---|---|---|"];
    let tableSize = table.join("\n").length;
    const more = (k: number): string => `| … | | | +${plural(k, "more package")} |`;
    for (const [i, r] of rows.entries()) {
      const reserve = i === rows.length - 1 ? 0 : more(rows.length).length + 1;
      if (tableSize + r.length + 1 + reserve > budget / 2) {
        droppedRows = rows.length - i;
        table.push(more(droppedRows));
        break;
      }
      table.push(r);
      tableSize += r.length + 1;
    }
    out.push(table.join("\n"), "");
    size += table.join("\n").length + 2;
  }
  // Blocks go in order until one doesn't fit; it and everything after it are left out.
  let droppedBlocks = 0;
  for (const block of [...sections, ...tail]) {
    if (droppedBlocks === 0 && size + block.length + 2 <= budget) {
      out.push(block, "");
      size += block.length + 2;
    } else droppedBlocks++;
  }
  if (droppedRows > 0 || droppedBlocks > 0) out.push(note(droppedRows, droppedBlocks), "");
  return `${out.join("\n").trimEnd()}\n`;
}
