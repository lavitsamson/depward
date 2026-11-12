// Turns the deltas into findings. Spec: docs/specs/diff.md § Findings. Every ID here is
// catalogued in docs/findings.md (section "Diff").

import { isIP } from "node:net";
import { isSensitiveEnvKey, type Capability, type PackageProfile } from "@depward/analyzer";
import {
  compareFindings,
  compareSeverity,
  escapeUnsafe,
  findingDocsUrl,
  isTrustedPublish,
  publisherChange,
  type Evidence,
  type Finding,
  type Severity,
  type VersionMeta,
} from "@depward/core";
import { publisherName, SCRIPT_NAMES } from "./deltas.ts";
import type { DiffContext, PackageDiff } from "./types.ts";

/** Every finding ID `diffPackages` can emit. Stable public API, catalogued in docs/findings.md. */
export const DIFF_FINDING_IDS = [
  "diff-new-install-script",
  "diff-new-capability",
  "diff-new-network-in-non-network-pkg",
  "diff-new-sensitive-env",
  "diff-new-endpoint",
  "diff-new-obfuscation",
  "diff-new-dependency",
  "diff-publisher-changed",
  "diff-provenance-dropped",
  "diff-semver-mismatch",
] as const;

/** Most evidence entries per finding. */
export const MAX_EVIDENCE = 10;

/** New capabilities that are `high` instead of `medium`. */
export const HIGH_RISK_CAPABILITIES: ReadonlySet<Capability> = new Set(["child_process", "dynamic_code", "native_addon"]);

/** Scripts npm runs on install (`prepare` is not run for registry installs). */
const INSTALL_SCRIPTS = SCRIPT_NAMES.filter((s) => s !== "prepare");

const ENUMERATION = /^enumerates process\.env\b/;

/** Inputs to the rules: the deltas plus the two sides they came from. */
export interface RuleInput {
  delta: Omit<PackageDiff, "findings" | "risk">;
  a: PackageProfile;
  b: PackageProfile;
  metaA: VersionMeta;
  metaB: VersionMeta;
  ctx: DiffContext;
}

function cap(evidence: Evidence[]): Evidence[] {
  if (evidence.length <= MAX_EVIDENCE) return evidence;
  return [...evidence.slice(0, MAX_EVIDENCE), { detail: `and ${evidence.length - MAX_EVIDENCE} more` }];
}

/** Host part of a normalized endpoint (`scheme://host[:port]/path`, host, or IP). */
export function endpointHost(endpoint: string): string {
  const rest = endpoint.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const bracketed = /^\[([^\]]*)\]/.exec(rest);
  if (bracketed) return bracketed[1] ?? "";
  if (isIP(rest) === 6) return rest;
  return rest.split(/[/:?#]/, 1)[0] ?? "";
}

/** True when the endpoint's host is an IP literal. */
export function isRawIpEndpoint(endpoint: string): boolean {
  return isIP(endpointHost(endpoint)) !== 0;
}

const CORE = /^v?(\d+)\.(\d+)\.(\d+)/;

/** True when `to` has the same major and minor as `from` and a higher patch. Prerelease tags are ignored. */
export function isPatchBump(from: string, to: string): boolean {
  const a = CORE.exec(from);
  const b = CORE.exec(to);
  if (!a || !b) return false;
  return a[1] === b[1] && a[2] === b[2] && Number(b[3]) > Number(a[3]);
}

function enumerations(p: PackageProfile): Evidence[] {
  return p.signals
    .filter((s) => s.id === "env-sensitive-read")
    .flatMap((s) => s.evidence)
    .filter((e) => e.detail !== undefined && ENUMERATION.test(e.detail));
}

/** Builds every finding for one package diff, sorted. */
export function diffFindings(input: RuleInput): Finding[] {
  const { delta, a, b, metaA, metaB, ctx } = input;
  const out: Finding[] = [];
  const pkg = delta.name;
  const from = escapeUnsafe(delta.from, 64);
  const add = (id: string, severity: Severity, message: string, evidence: Evidence[]): void => {
    out.push({ id, severity, package: pkg, version: delta.to, message, evidence: cap(evidence), docsUrl: findingDocsUrl(id) });
  };

  // Install scripts that are new or changed.
  const scripts = INSTALL_SCRIPTS.filter((s) => delta.scriptDelta[s]?.to !== undefined);
  if (scripts.length > 0) {
    add(
      "diff-new-install-script",
      "high",
      `adds or changes install scripts since ${from}: ${scripts.join(", ")}`,
      scripts.map((s) => {
        const change = delta.scriptDelta[s] ?? {};
        return {
          file: "package.json",
          snippet: `${s}: ${escapeUnsafe(change.to ?? "")}`,
          detail: change.from === undefined ? "new script" : `was: ${escapeUnsafe(change.from)}`,
        };
      }),
    );
  }

  // New capabilities. `net` is reported once, by the network rule.
  for (const c of delta.capabilityDelta.added) {
    const evidence = b.capabilities[c].map((u) => ({ file: u.file, ...(u.line === undefined ? {} : { line: u.line }), snippet: u.evidence }));
    if (c === "net") {
      add("diff-new-network-in-non-network-pkg", "high", `uses the network; ${from} did not`, evidence);
    } else {
      add("diff-new-capability", HIGH_RISK_CAPABILITIES.has(c) ? "high" : "medium", `new capability: ${c} (not used in ${from})`, evidence);
    }
  }

  // Sensitive environment access.
  const sensitiveKeys = delta.envKeyDelta.added.filter(isSensitiveEnvKey);
  const newEnumeration = enumerations(a).length === 0 ? enumerations(b) : [];
  if (sensitiveKeys.length > 0 || newEnumeration.length > 0) {
    const what = [
      ...(sensitiveKeys.length > 0 ? [`sensitive environment variables (${sensitiveKeys.map((k) => escapeUnsafe(k, 64)).join(", ")})`] : []),
      ...(newEnumeration.length > 0 ? ["the whole environment"] : []),
    ];
    const keyEvidence = sensitiveKeys.map((k) => ({ snippet: `process.env.${escapeUnsafe(k, 100)}`, detail: "new sensitive key" }));
    add("diff-new-sensitive-env", "high", `newly reads ${what.join(" and ")}`, [...newEnumeration, ...keyEvidence]);
  }

  // Hardcoded endpoints.
  if (delta.endpointDelta.added.length > 0) {
    const ips = delta.endpointDelta.added.filter(isRawIpEndpoint);
    const evidence = delta.endpointDelta.added.map((e) => ({ snippet: escapeUnsafe(e), ...(ips.includes(e) ? { detail: "raw IP" } : {}) }));
    const n = delta.endpointDelta.added.length;
    add(
      "diff-new-endpoint",
      ips.length > 0 ? "high" : "medium",
      `${n} new hardcoded endpoint${n === 1 ? "" : "s"}${ips.length > 0 ? `, ${ips.length} raw IP` : ""}`,
      // Raw IPs first, so the cap never hides them.
      evidence.toSorted((x, y) => Number("detail" in y) - Number("detail" in x)),
    );
  }

  // Obfuscation or an encoded payload that A didn't have.
  const hidden = delta.signalDelta.added.filter((s) => s.id === "obfuscation" || s.id === "encoded-payload");
  if (hidden.length > 0) {
    const ids = [...new Set(hidden.map((s) => s.id))];
    add("diff-new-obfuscation", "critical", `new ${ids.join(" and ")} not present in ${from}`, hidden.flatMap((s) => s.evidence));
  }

  // New dependencies. Lockfile mode raises young ones to high.
  for (const dep of delta.dependencyDelta.added) {
    const young = ctx.isYoungDependency?.(dep) === true;
    add(
      "diff-new-dependency",
      young ? "high" : "low",
      `new dependency: ${escapeUnsafe(dep, 214)}${young ? " (itself published recently)" : ""}`,
      [{ file: "package.json", snippet: escapeUnsafe(dep, 214), ...(young ? { detail: "package-too-new" } : {}) }],
    );
  }

  // Publisher.
  const publisher = publisherFinding(metaA, metaB, ctx);
  if (publisher !== null) {
    add("diff-publisher-changed", "high", `published by ${escapeUnsafe(publisher.to, 100)}, not by a recent publisher (${publisher.previous.map((p) => escapeUnsafe(p, 100)).join(", ")})`, [
      { detail: `${from} was published by ${escapeUnsafe(publisherName(metaA) ?? "unknown", 100)}` },
    ]);
  }

  if (delta.provenanceDelta === "dropped") {
    add("diff-provenance-dropped", "high", `has no provenance attestation; ${from} had one`, []);
  }

  // A patch release should not gain capabilities or install scripts.
  if (isPatchBump(delta.from, delta.to) && (delta.capabilityDelta.added.length > 0 || scripts.length > 0)) {
    const what = [...delta.capabilityDelta.added.map((c) => `capability ${c}`), ...scripts.map((s) => `${s} script`)];
    add("diff-semver-mismatch", "medium", `patch release adds ${what.join(", ")}`, [{ detail: `${from} → ${escapeUnsafe(delta.to, 64)}` }]);
  }

  return out.toSorted(compareFindings);
}

function publisherFinding(metaA: VersionMeta, metaB: VersionMeta, ctx: DiffContext): { to: string; previous: readonly string[] } | null {
  if (ctx.packument !== undefined) {
    const change = publisherChange(ctx.packument, metaB, ctx.now === undefined ? {} : { now: ctx.now });
    return change === null ? null : { to: change.publisher, previous: change.previous };
  }
  const was = publisherName(metaA);
  const now = publisherName(metaB);
  if (was === null || now === null || was === now || isTrustedPublish(metaB)) return null;
  return { to: now, previous: [was] };
}

/** The highest severity, escalated to `critical` when two or more findings are `high`. `info` when empty. */
export function diffRisk(findings: readonly Finding[]): Severity {
  if (findings.filter((f) => f.severity === "high").length >= 2) return "critical";
  return findings.map((f) => f.severity).toSorted(compareSeverity)[0] ?? "info";
}
