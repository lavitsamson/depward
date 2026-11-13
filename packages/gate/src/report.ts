// Machine-readable form of a Decision, shared by the CLI (`--format json`) and the MCP
// server. Keys are in a fixed order so output is deterministic. Text is not escaped
// beyond JSON's own escaping: consumers that print it must sanitize it.

import { sortFindings, type Evidence, type Finding } from "@depward/core";
import type { DecidedFinding } from "./policy/engine.ts";
import type { Decision, PackageDecision } from "./gate.ts";

/** Bumped on any breaking change to {@link DecisionJson}. */
export const DECISION_JSON_VERSION = 1;

/** One finding with the action the policy gave it. */
export interface DecidedFindingJson {
  id: string;
  severity: Finding["severity"];
  package: string;
  version?: string;
  message: string;
  evidence: Evidence[];
  docsUrl: string;
  action: DecidedFinding["action"];
  actionSource: DecidedFinding["source"];
}

/** One package's decision. */
export interface PackageDecisionJson {
  name: string;
  range: string;
  source: PackageDecision["source"];
  version: string | null;
  action: PackageDecision["action"];
  listed: PackageDecision["listed"];
  suggestion: PackageDecision["suggestion"];
  weeklyDownloads: number | null;
  analyzed: boolean;
  /** The locked version this request was diffed against (the update path), or `null`. */
  update: PackageDecision["update"];
  errors: { code: string; message: string }[];
  errorAction: PackageDecision["errorAction"];
  findings: DecidedFindingJson[];
}

/** The JSON shape of a {@link Decision}. */
export interface DecisionJson {
  decisionVersion: typeof DECISION_JSON_VERSION;
  tool: { name: string; version?: string };
  action: Decision["action"];
  reasons: string[];
  packages: PackageDecisionJson[];
  /** Command-level findings (`unparseable-command`). */
  findings: DecidedFindingJson[];
}

function evidence(e: Evidence): Evidence {
  const out: Evidence = {};
  if (e.file !== undefined) out.file = e.file;
  if (e.line !== undefined) out.line = e.line;
  if (e.snippet !== undefined) out.snippet = e.snippet;
  if (e.detail !== undefined) out.detail = e.detail;
  return out;
}

function decided(list: readonly DecidedFinding[]): DecidedFindingJson[] {
  const byFinding = new Map(list.map((d) => [d.finding, d]));
  return sortFindings(list.map((d) => d.finding)).map((f) => {
    const d = byFinding.get(f) as DecidedFinding;
    return {
      id: f.id,
      severity: f.severity,
      package: f.package,
      ...(f.version === undefined ? {} : { version: f.version }),
      message: f.message,
      evidence: f.evidence.map(evidence),
      docsUrl: f.docsUrl,
      action: d.action,
      actionSource: d.source,
    };
  });
}

/** Every finding in a decision (package and command level), sorted. */
export function decisionFindings(decision: Decision): Finding[] {
  return sortFindings([...decision.packages.flatMap((p) => p.findings), ...decision.findings].map((d) => d.finding));
}

/**
 * Converts a decision to plain JSON data. Packages keep their request order; findings
 * are sorted by severity, package, id.
 */
export function serializeDecision(decision: Decision, tool: { name: string; version?: string } = { name: "depward" }): DecisionJson {
  return {
    decisionVersion: DECISION_JSON_VERSION,
    tool: { name: tool.name, ...(tool.version === undefined ? {} : { version: tool.version }) },
    action: decision.action,
    reasons: [...decision.reasons],
    packages: decision.packages.map((p) => ({
      name: p.name,
      range: p.range,
      source: p.source,
      version: p.version,
      action: p.action,
      listed: p.listed,
      suggestion: { ...p.suggestion },
      weeklyDownloads: p.weeklyDownloads,
      analyzed: p.analyzed,
      update: p.update === null ? null : { from: p.update.from, lockfile: p.update.lockfile },
      errors: p.errors.map((e) => ({ code: e.code, message: e.message })),
      errorAction: p.errorAction,
      findings: decided(p.findings),
    })),
    findings: decided(decision.findings),
  };
}
