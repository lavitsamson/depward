/** Finding severity, from least to most severe. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** All severities, ordered from most to least severe. */
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** A piece of evidence supporting a finding. All fields come from untrusted package data. */
export interface Evidence {
  file?: string;
  line?: number;
  snippet?: string;
  detail?: string;
}

/**
 * A single result from any depward check. `id` is stable public API; every ID is
 * catalogued in `docs/findings.md`.
 */
export interface Finding {
  id: string;
  severity: Severity;
  package: string;
  version?: string;
  message: string;
  evidence: Evidence[];
  docsUrl: string;
}

/** Sort comparator: most severe first. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
}

// Code-unit comparison, so output does not depend on the machine's locale.
function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Sort comparator giving deterministic output: severity, then package, then id. */
export function compareFindings(a: Finding, b: Finding): number {
  return compareSeverity(a.severity, b.severity) || compareStrings(a.package, b.package) || compareStrings(a.id, b.id);
}

/** Documentation URL for a finding ID (its entry in `docs/findings.md`). */
export function findingDocsUrl(id: string): string {
  return `https://github.com/lavitsamson/depward/blob/main/docs/findings.md#${id}`;
}
