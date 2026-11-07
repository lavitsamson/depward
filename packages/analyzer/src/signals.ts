import { compareFindings, compareSeverity, findingDocsUrl, type Evidence, type Finding, type Severity } from "@depward/core";
import type { PackageProfile, Signal, SignalId } from "./types.ts";

/** Default severity of each signal (spec: analyzer.md § Risk signals). */
export const SIGNAL_SEVERITY: Readonly<Record<SignalId, Severity>> = {
  "install-script": "medium",
  "install-script-network": "high",
  "env-sensitive-read": "high",
  "env-exfil-pattern": "critical",
  "fs-sensitive-path": "high",
  obfuscation: "high",
  "encoded-payload": "high",
  "high-entropy-string": "low",
  "hardcoded-endpoint": "info",
  "raw-ip-endpoint": "medium",
  "native-binary": "medium",
  "unparseable-file": "low",
  "oversized-file": "low",
  "minified-only": "info",
};

const cmp = (a: string | undefined, b: string | undefined): number => ((a ?? "") < (b ?? "") ? -1 : (a ?? "") > (b ?? "") ? 1 : 0);

/** Builds a signal with its default severity, deduplicating and capping the evidence. */
export function makeSignal(id: SignalId, message: string, evidence: Evidence[], maxEvidence: number): Signal {
  const seen = new Set<string>();
  const unique: Evidence[] = [];
  for (const e of evidence) {
    const key = JSON.stringify([e.file, e.line, e.snippet, e.detail]);
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(e);
    }
  }
  unique.sort((a, b) => cmp(a.file, b.file) || (a.line ?? 0) - (b.line ?? 0) || cmp(a.snippet, b.snippet) || cmp(a.detail, b.detail));
  const kept = unique.slice(0, maxEvidence);
  if (unique.length > maxEvidence) kept.push({ detail: `and ${unique.length - maxEvidence} more` });
  return { id, severity: SIGNAL_SEVERITY[id], message, evidence: kept };
}

/** Sort comparator: severity, then id, then first evidence file, then message. */
export function compareSignals(a: Signal, b: Signal): number {
  return (
    compareSeverity(a.severity, b.severity) ||
    cmp(a.id, b.id) ||
    cmp(a.evidence[0]?.file, b.evidence[0]?.file) ||
    cmp(a.message, b.message)
  );
}

/** Converts a profile's signals to {@link Finding}s, sorted by severity, package, then id. */
export function profileFindings(profile: PackageProfile): Finding[] {
  return profile.signals
    .map((s) => ({
      id: s.id,
      severity: s.severity,
      package: profile.name,
      version: profile.version,
      message: s.message,
      evidence: s.evidence,
      docsUrl: findingDocsUrl(s.id),
    }))
    .toSorted(compareFindings);
}
