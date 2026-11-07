import type { Evidence, Finding } from "../findings.ts";
import { countBySeverity, sortFindings, type ToolInfo } from "./common.ts";

/** Version of the JSON report shape. Bumped on breaking changes. */
export const JSON_REPORT_VERSION = 1;

/** Options for {@link renderJson}. */
export interface JsonOptions {
  tool?: ToolInfo;
}

/**
 * Renders a machine-readable report:
 * `{ reportVersion, tool, summary: { total, critical, …, info }, findings }`, with
 * findings sorted and keys in a fixed order. Text is not escaped beyond JSON's own
 * escaping; consumers that print it must sanitize it.
 */
export function renderJson(findings: readonly Finding[], opts: JsonOptions = {}): string {
  const tool: Record<string, string> = { name: opts.tool?.name ?? "depward" };
  if (opts.tool?.version !== undefined) tool["version"] = opts.tool.version;
  const report = {
    reportVersion: JSON_REPORT_VERSION,
    tool,
    summary: { total: findings.length, ...countBySeverity(findings) },
    findings: sortFindings(findings).map(normalize),
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

function normalize(f: Finding): Record<string, unknown> {
  const out: Record<string, unknown> = { id: f.id, severity: f.severity, package: f.package };
  if (f.version !== undefined) out["version"] = f.version;
  out["message"] = f.message;
  out["evidence"] = f.evidence.map(normalizeEvidence);
  out["docsUrl"] = f.docsUrl;
  return out;
}

function normalizeEvidence(e: Evidence): Evidence {
  const out: Evidence = {};
  if (e.file !== undefined) out.file = e.file;
  if (e.line !== undefined) out.line = e.line;
  if (e.snippet !== undefined) out.snippet = e.snippet;
  if (e.detail !== undefined) out.detail = e.detail;
  return out;
}
