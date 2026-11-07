export { countBySeverity, escapeUnsafe, sortFindings, summaryText, type ToolInfo } from "./common.ts";
export { JSON_REPORT_VERSION, renderJson, type JsonOptions } from "./json.ts";
export { escapeMarkdown, renderMarkdown, type MarkdownOptions } from "./markdown.ts";
export { renderSarif, type SarifLocation, type SarifOptions } from "./sarif.ts";
export { colorEnabled, renderTerminal, type TerminalOptions } from "./terminal.ts";

import type { Finding } from "../findings.ts";
import type { ToolInfo } from "./common.ts";
import { renderJson } from "./json.ts";
import { renderMarkdown } from "./markdown.ts";
import { renderSarif, type SarifOptions } from "./sarif.ts";
import { renderTerminal } from "./terminal.ts";

/** Output formats accepted by `--format`. */
export type ReportFormat = "terminal" | "json" | "markdown" | "sarif";

/** Every {@link ReportFormat}. */
export const REPORT_FORMATS: readonly ReportFormat[] = ["terminal", "json", "markdown", "sarif"];

/** Options for {@link renderReport}; each renderer uses the fields it understands. */
export interface ReportOptions {
  tool?: ToolInfo;
  /** Terminal only. */
  color?: boolean;
  /** Terminal and Markdown heading prefix. */
  title?: string;
  /** SARIF only. */
  locate?: SarifOptions["locate"];
}

/** Renders findings in the given format. Output always ends with a newline. */
export function renderReport(format: ReportFormat, findings: readonly Finding[], opts: ReportOptions = {}): string {
  const title = opts.title === undefined ? {} : { title: opts.title };
  const tool = opts.tool === undefined ? {} : { tool: opts.tool };
  switch (format) {
    case "terminal":
      return renderTerminal(findings, { color: opts.color ?? false, ...title });
    case "json":
      return renderJson(findings, tool);
    case "markdown":
      return renderMarkdown(findings, title);
    case "sarif":
      return renderSarif(findings, { ...tool, ...(opts.locate === undefined ? {} : { locate: opts.locate }) });
  }
}
