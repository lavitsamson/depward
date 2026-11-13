// The MCP tool `diff_versions` (M3.7): the behavioral diff of one package update, the
// same as `depward diff <name> <from> <to> --json`. Spec: docs/specs/gate.md §MCP server.
// SDK: @modelcontextprotocol/server v2 (ADR 0004), API as in server.ts.

import { assertPackageName, escapeUnsafe, type DepwardConfig, type RegistryClient } from "@depward/core";
import { applyPolicy, diffVersions, packageView, serializeDiff, type DiffView } from "@depward/diff";
import { createPolicy, type GateOptions } from "@depward/gate";

/** Findings listed in the text block; `structuredContent` always has all of them. */
const MAX_TEXT_FINDINGS = 25;

export const DIFF_DESCRIPTION: string =
  "Call this BEFORE updating an npm dependency to another version, or when reviewing a dependency update. " +
  "depward downloads both versions' tarballs (it never runs them) and reports what the new version does that the old one did not: new install scripts, network use, credential reads, hardcoded endpoints, obfuscation, new dependencies, and publisher or provenance changes. " +
  'Returns a risk level (critical, high, medium, low, info) with findings. On "critical", do not update; stay on the old version or ask the user. On "high", tell the user what changed before updating.';

/** The text block for the model: the risk line, the counted findings, failures, and what to do next. */
export function diffText(view: DiffView): string {
  const p = view.packages[0];
  if (p === undefined) return "depward: nothing to diff";
  const label = escapeUnsafe(`${p.name} ${p.from ?? "?"} → ${p.to}`, 300);
  const lines = [`depward: risk ${view.risk} for ${label}`];
  for (const f of p.findings.slice(0, MAX_TEXT_FINDINGS)) lines.push(`- ${f.severity} ${escapeUnsafe(f.id, 80)}: ${escapeUnsafe(f.message, 300)}`);
  if (p.findings.length > MAX_TEXT_FINDINGS) lines.push(`- … ${p.findings.length - MAX_TEXT_FINDINGS} more in structuredContent`);
  const allowed = p.allowedFindings?.length ?? 0;
  if (allowed > 0) lines.push(`${allowed} finding${allowed === 1 ? "" : "s"} allowed by the project's config (not counted).`);
  for (const e of p.errors) lines.push(`- lookup failed (${escapeUnsafe(e.code, 40)}): ${escapeUnsafe(e.message, 300)}`);

  const old = escapeUnsafe(p.from ?? "the current version", 100);
  if (view.risk === "critical") lines.push(`Do not update. Stay on ${old}, or ask the user.`);
  else if (view.risk === "high") lines.push("Tell the user what changed and let them decide before updating.");
  else if (p.errors.length > 0) lines.push("Part of the diff could not be checked. Tell the user before updating.");
  else lines.push("depward found nothing in this update that needs attention.");
  return lines.join("\n");
}

/** The tool's input (validated by the server's input schema). */
export interface DiffInput {
  name: string;
  from: string;
  to: string;
}

/** What {@link runDiffVersions} needs from the server. */
export interface DiffToolContext {
  registry: RegistryClient;
  config: DepwardConfig;
  gate: Partial<GateOptions>;
  version: string;
}

/**
 * Diffs `from` → `to` with the project's policy applied. An invalid package name throws
 * `INVALID_ARGUMENT` (a tool error); a failed lookup is reported in the result instead.
 */
export async function runDiffVersions(input: DiffInput, ctx: DiffToolContext): Promise<{ view: DiffView; json: Record<string, unknown> }> {
  assertPackageName(input.name);
  const policy = createPolicy(ctx.config);
  const { gate } = ctx;
  const result = await diffVersions(input.name, input.from, input.to, {
    registry: ctx.registry,
    policy,
    ...(gate.analysisCache === undefined ? {} : { analysisCache: gate.analysisCache }),
    ...(gate.now === undefined ? {} : { now: gate.now }),
    ...(gate.tarLimits === undefined ? {} : { tarLimits: gate.tarLimits }),
    ...(gate.analyze === undefined ? {} : { analyze: gate.analyze }),
  });
  const view = packageView(applyPolicy(result, policy));
  return { view, json: serializeDiff(view, { name: "depward", version: ctx.version }) };
}
