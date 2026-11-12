// Applies the project config to diff results, and decides `--fail-on`.
// Spec: docs/specs/diff.md § Risk and --fail-on.
//
// - A finding whose ID the config's `policy` sets to `allow` moves to `allowedFindings`.
// - A package on the `allow` list keeps its findings visible, all as allowed.
// - A package on the `deny` list gets the gate's `denylisted` finding, and its risk is
//   `critical`, whatever else was found.
// Risk is then recomputed from the findings that still count. `ask` and `deny` policy
// overrides don't change diff risk.

import { compareSeverity, sortFindings, type Severity } from "@depward/core";
import type { Policy } from "@depward/gate";
import { diffRisk } from "../rules.ts";
import { maxSeverity } from "./check.ts";
import type { PackageChangeResult } from "./types.ts";

/** Severities `--fail-on` accepts, plus `none` (never fail). */
export const FAIL_ON_LEVELS = ["critical", "high", "medium", "low", "info", "none"] as const;

/** A `--fail-on` threshold. */
export type FailOn = (typeof FAIL_ON_LEVELS)[number];

/** Returns `result` with the config's policy applied (see the module comment). Pure. */
export function applyPolicy(result: PackageChangeResult, policy: Policy): PackageChangeResult {
  const match = policy.listed(result.name, result.to);
  const verdict = policy.decidePackage({ name: result.name, version: result.to, findings: result.findings, errors: [] });
  const counted = match?.list === "allow" ? [] : verdict.findings.filter((d) => d.source !== "config" || d.action !== "allow").map((d) => d.finding);
  const allowed = verdict.findings.map((d) => d.finding).filter((f) => !counted.includes(f));
  let risk: Severity = result.kind === "updated" ? diffRisk(counted) : maxSeverity(counted);
  if (match?.list === "deny") risk = "critical";
  return {
    ...result,
    findings: sortFindings(counted),
    allowedFindings: sortFindings([...(result.allowedFindings ?? []), ...allowed]),
    listed: match,
    risk,
  };
}

/**
 * True when a package's risk reaches `failOn`. Packages without counted findings never
 * fail (their risk is only `info` by default), so `--fail-on info` means "any finding".
 */
export function reachesFailOn(packages: readonly PackageChangeResult[], failOn: FailOn): boolean {
  if (failOn === "none") return false;
  return packages.some((p) => (p.findings.length > 0 || p.listed?.list === "deny") && compareSeverity(p.risk, failOn) <= 0);
}
