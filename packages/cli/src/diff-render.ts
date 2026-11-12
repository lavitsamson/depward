// Renderings of `depward diff` results. Every package-controlled string goes through
// escapeUnsafe / escapeMarkdown before printing (CLAUDE.md: strip ANSI escapes and
// control characters). JSON is escaped by JSON itself; consumers must sanitize it.

import {
  SEVERITIES,
  escapeMarkdown,
  escapeUnsafe,
  renderMarkdown,
  renderSarif,
  type DepwardError,
  type Finding,
  type Severity,
  type ToolInfo,
} from "@depward/core";
import type { LockfileSummary, PackageChangeResult } from "@depward/diff";

/** Version of the `depward diff --format json` document. Bumped on breaking changes. */
export const DIFF_JSON_VERSION: number = 1;

/** What `depward diff` reports: one package (from the CLI arguments) or a lockfile change. */
export interface DiffView {
  packages: PackageChangeResult[];
  /** Every finding, sorted. */
  findings: Finding[];
  risk: Severity;
  lockfiles: LockfileSummary[];
  skipped: string[];
  /** Base commit, in lockfile mode. */
  base: string | null;
  /** Head ref, or `null` for the working tree (lockfile mode) or no head (single package). */
  head: string | null;
}

const SGR: Record<Severity, string> = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };

/** `name from → to` or `name@to`. */
export function changeLabel(p: PackageChangeResult): string {
  return p.from === undefined ? `${p.name}@${p.to}` : `${p.name} ${p.from} → ${p.to}`;
}

function counts(packages: readonly PackageChangeResult[]): string {
  const n = packages.length;
  if (n === 0) return "no dependency changes";
  const parts = SEVERITIES.map((s) => [s, packages.filter((p) => p.risk === s).length] as const)
    .filter(([, c]) => c > 0)
    .map(([s, c]) => `${c} ${s}`);
  return `${n} package change${n === 1 ? "" : "s"}: ${parts.join(", ")}`;
}

const errorLine = (e: DepwardError): string => `${e.code}: ${e.message}`;

/** The terminal view. Packages without findings are counted, not listed, unless `verbose`. */
export function renderDiffTerminal(view: DiffView, opts: { color?: boolean; verbose?: boolean } = {}): string {
  const paint = (sgr: string, s: string): string => (opts.color ? `\u001b[${sgr}m${s}\u001b[0m` : s);
  const lines = [`depward diff: ${paint(SGR[view.risk], view.risk)} (${counts(view.packages)})`];
  if (view.base !== null) lines.push(`base ${view.base.slice(0, 12)}, head ${view.head === null ? "working tree" : escapeUnsafe(view.head, 100)}`);
  for (const l of view.lockfiles) {
    for (const f of l.findings) lines.push(`${escapeUnsafe(l.path, 200)}: ${escapeUnsafe(f.message, 300)}`);
  }

  let hidden = 0;
  for (const p of view.packages) {
    const shown = opts.verbose ? p.findings : p.findings.filter((f) => f.severity !== "info");
    if (shown.length === 0 && p.errors.length === 0 && !opts.verbose) {
      hidden++;
      continue;
    }
    lines.push("", `  ${paint(SGR[p.risk], p.risk.toUpperCase().padEnd(8))}  ${escapeUnsafe(changeLabel(p), 200)}  (${p.kind})`);
    for (const f of shown) {
      lines.push(`            ${paint("1", escapeUnsafe(f.id, 80))} [${f.severity}]: ${escapeUnsafe(f.message, 300)}`);
      const where = f.evidence.find((e) => e.file !== undefined);
      if (where?.file !== undefined) lines.push(`              at ${escapeUnsafe(where.file, 200)}${where.line === undefined ? "" : `:${where.line}`}`);
    }
    for (const e of p.errors) lines.push(`            ${paint("1", "lookup failed")}: ${escapeUnsafe(errorLine(e), 300)}`);
  }
  if (hidden > 0) lines.push("", `${hidden} package change${hidden === 1 ? "" : "s"} with no findings not shown (--verbose shows them).`);
  if (opts.verbose && view.skipped.length > 0) lines.push("", `skipped (local or bundled): ${view.skipped.map((s) => escapeUnsafe(s, 200)).join(", ")}`);
  return `${lines.join("\n")}\n`;
}

/** The Markdown view: a summary table, then the standard per-package findings report. */
export function renderDiffMarkdown(view: DiffView): string {
  const flagged = view.packages.filter((p) => p.risk !== "info" && p.risk !== "low");
  const n = view.packages.length;
  const heading = `## depward: ${n} dependency change${n === 1 ? "" : "s"}${flagged.length > 0 ? `, ${flagged.length} need${flagged.length === 1 ? "s" : ""} review` : ""}`;
  if (view.packages.length === 0) return `${heading}\n`;
  const rows = view.packages.map((p) => {
    const why = [...new Set(p.findings.filter((f) => f.severity !== "info").map((f) => f.id))].slice(0, 4);
    const change = p.from === undefined ? `${p.kind} ${p.to}` : `${p.from} → ${p.to}`;
    return `| ${p.risk} | <code>${escapeMarkdown(p.name, 214)}</code> | ${escapeMarkdown(change, 100)} | ${why.map((id) => escapeMarkdown(id, 60)).join(" · ")} |`;
  });
  const table = `| Risk | Package | Change | Why |\n|---|---|---|---|\n${rows.join("\n")}\n`;
  return `${heading}\n\n${table}\n${renderMarkdown(view.findings, { title: "depward diff findings" })}`;
}

/** SARIF, with each finding located in the lockfile its package came from. */
export function renderDiffSarif(view: DiffView, tool: ToolInfo): string {
  const lockfileOf = new Map(view.packages.map((p) => [p.name, p.lockfiles[0]]));
  return renderSarif(view.findings, { tool, locate: (f) => ({ uri: lockfileOf.get(f.package) ?? "package.json", line: 1 }) });
}

/** The JSON document of `depward diff --format json`. Key order is fixed. */
export function serializeDiff(view: DiffView, tool: ToolInfo): Record<string, unknown> {
  return {
    reportVersion: DIFF_JSON_VERSION,
    tool: { name: tool.name, ...(tool.version === undefined ? {} : { version: tool.version }) },
    base: view.base,
    head: view.head,
    risk: view.risk,
    lockfiles: view.lockfiles,
    packages: view.packages.map((p) => ({
      kind: p.kind,
      name: p.name,
      ...(p.from === undefined ? {} : { from: p.from }),
      to: p.to,
      lockfiles: p.lockfiles,
      risk: p.risk,
      findings: p.findings,
      errors: p.errors.map((e) => ({ code: e.code, message: e.message })),
      ...(p.diff === undefined
        ? {}
        : {
            delta: {
              capabilities: p.diff.capabilityDelta,
              signals: { added: [...new Set(p.diff.signalDelta.added.map((s) => s.id))], removed: [...new Set(p.diff.signalDelta.removed.map((s) => s.id))] },
              scripts: p.diff.scriptDelta,
              dependencies: p.diff.dependencyDelta,
              files: p.diff.fileDelta,
              endpoints: p.diff.endpointDelta,
              envKeys: p.diff.envKeyDelta,
              ...(p.diff.publisherDelta === undefined ? {} : { publisher: p.diff.publisherDelta }),
              ...(p.diff.provenanceDelta === undefined ? {} : { provenance: p.diff.provenanceDelta }),
            },
          }),
    })),
    skipped: view.skipped,
  };
}
