// SARIF 2.1.0 for GitHub code scanning.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html
// GitHub requirements (checked 2026-11-07):
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
// - every result needs a location (only the first is used) and partialFingerprints;
// - rules need shortDescription, fullDescription, and help text (<= 1024 chars each);
// - properties["security-severity"] is a string in (0, 10]: > 9 critical, 7-8.9 high,
//   4-6.9 medium, 0.1-3.9 low; it only applies to rules tagged "security".

import { createHash } from "node:crypto";
import type { Finding, Severity } from "../findings.ts";
import { escapeUnsafe, evidenceLocation, packageLabel, sortFindings, type ToolInfo } from "./common.ts";

/** Where a finding is reported in the repository. */
export interface SarifLocation {
  /** Path relative to the repository root, with `/` separators. */
  uri: string;
  /** 1-based. Default 1. */
  line?: number;
}

/** Options for {@link renderSarif}. */
export interface SarifOptions {
  tool?: ToolInfo;
  /**
   * Maps a finding to a repository file. Findings describe packages, not repository code,
   * so this is usually the manifest or lockfile that pulls the package in. Default:
   * `package.json`, line 1.
   */
  locate?: (finding: Finding) => SarifLocation;
}

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};
// Omitted for info: GitHub treats 0.0 as "no security severity".
const SECURITY_SEVERITY: Record<Severity, string | undefined> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: undefined,
};

const SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const INFO_URI = "https://github.com/lavitsamson/depward";

// Untrusted text is made visible-safe (no ANSI, controls, or bidi overrides) and capped.
const cap = (s: string, max: number): string => escapeUnsafe(s, max);
const safeUrl = (u: string): boolean => /^https:\/\/[^\s<>"'()]+$/.test(u);
const nonEmpty = (s: string, fallback: string): string => (s.trim() === "" ? fallback : s);

/**
 * Renders a SARIF 2.1.0 log with one run. Rules are the distinct finding IDs; a rule's
 * default level and security severity come from its most severe finding. Each result
 * has a stable `primaryLocationLineHash` derived from (id, package, version), so
 * re-uploads update alerts instead of duplicating them.
 */
export function renderSarif(findings: readonly Finding[], opts: SarifOptions = {}): string {
  const sorted = sortFindings(findings);
  const locate = opts.locate ?? ((): SarifLocation => ({ uri: "package.json", line: 1 }));

  // sortFindings is most-severe first, so the first finding per id sets the rule.
  const firstById = new Map<string, Finding>();
  for (const f of sorted) if (!firstById.has(f.id)) firstById.set(f.id, f);
  const ids = [...firstById.keys()].toSorted();
  const index = new Map(ids.map((id, i) => [id, i]));

  const rules = ids.map((id) => {
    const f = firstById.get(id) as Finding;
    const description = cap(nonEmpty(f.message, id), 1024);
    const properties: Record<string, unknown> = { tags: ["security", "supply-chain"], precision: "medium" };
    const sev = SECURITY_SEVERITY[f.severity];
    if (sev !== undefined) properties["security-severity"] = sev;
    return {
      id,
      name: cap(id, 255),
      shortDescription: { text: description },
      fullDescription: { text: safeUrl(f.docsUrl) ? cap(`${description}. See ${f.docsUrl}`, 1024) : description },
      help: safeUrl(f.docsUrl)
        ? { text: `See ${f.docsUrl}`, markdown: `See the [finding catalog](${f.docsUrl}).` }
        : { text: `Finding ${id}; see the depward finding catalog.` },
      ...(safeUrl(f.docsUrl) ? { helpUri: f.docsUrl } : {}),
      defaultConfiguration: { level: LEVEL[f.severity] },
      properties,
    };
  });

  const seen = new Map<string, number>();
  const results = sorted.map((f) => {
    const loc = locate(f);
    const key = `${f.id}\0${f.package}\0${f.version ?? ""}`;
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);
    const properties: Record<string, unknown> = { severity: f.severity, package: f.package };
    if (f.version !== undefined) properties["version"] = f.version;
    return {
      ruleId: f.id,
      ruleIndex: index.get(f.id) ?? 0,
      level: LEVEL[f.severity],
      message: { text: messageText(f) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: nonEmpty(loc.uri, "package.json") },
            region: { startLine: Math.max(1, Math.trunc(loc.line ?? 1)) },
          },
        },
      ],
      // The ":n" suffix keeps several findings with the same key distinct.
      partialFingerprints: { primaryLocationLineHash: `${hash}:${n + 1}` },
      properties,
    };
  });

  const driver: Record<string, unknown> = { name: opts.tool?.name ?? "depward", informationUri: INFO_URI };
  if (opts.tool?.version !== undefined) {
    driver["version"] = opts.tool.version;
    driver["semanticVersion"] = opts.tool.version;
  }
  driver["rules"] = rules;
  const log = { $schema: SCHEMA, version: "2.1.0", runs: [{ tool: { driver }, results }] };
  return `${JSON.stringify(log, null, 2)}\n`;
}

/** Plain-text message: the first sentence names the package; evidence follows. */
function messageText(f: Finding): string {
  const lines = [cap(`${packageLabel(f)}: ${nonEmpty(f.message, f.id)}.`, 500)];
  for (const e of f.evidence.slice(0, 20)) {
    const loc = evidenceLocation(e);
    const parts = [loc === undefined ? undefined : cap(loc, 200), e.snippet === undefined ? undefined : `"${cap(e.snippet, 200)}"`, e.detail === undefined ? undefined : cap(e.detail, 200)];
    const text = parts.filter((p) => p !== undefined).join(" ");
    if (text) lines.push(`- ${text}`);
  }
  return lines.join("\n");
}
