// `depward caps compare`: what the runtime layer observed vs the capability lockfile.
// Spec: docs/specs/caps.md § Runtime details. Same report and exit codes as `check`.

import { compareSeverity, findingDocsUrl, sortFindings, type Evidence, type Finding } from "@depward/core";
import { MAX_EVIDENCE, applyPolicy, type PackageChangeResult } from "@depward/diff";
import type { Policy } from "@depward/gate";
import { comparePackages, maxSeverity, referenceIndex, unapprovedReason, unapprovedSeverity, type CapsCheckReport, type CapsReference } from "./check.ts";
import { splitKey } from "./lockfile.ts";
import type { ObservedFile, ObservedUse } from "./runtime/store.ts";
import type { CapsLockfile } from "./types.ts";

/** Options for {@link compareObserved}. */
export interface CompareOptions {
  /** The project's policy (`createPolicy(config)`), applied as in `check`. Default: none. */
  policy?: Policy;
}

/** `caps-observed-unapproved` findings for observed capabilities `reference` doesn't list. */
export function observedFindings(name: string, version: string, uses: Readonly<Record<string, ObservedUse>>, reference: CapsReference | null): Finding[] {
  const approved = new Set(reference?.entry.capabilities ?? []);
  const against = unapprovedReason(name, version, reference);
  return Object.keys(uses)
    .toSorted()
    .filter((cap) => !approved.has(cap))
    .map((cap) => {
      const use = uses[cap] as ObservedUse;
      const evidence: Evidence[] = use.members.slice(0, MAX_EVIDENCE).map((m) => ({ snippet: m }));
      if (use.members.length > MAX_EVIDENCE) evidence.push({ detail: `and ${use.members.length - MAX_EVIDENCE} more` });
      evidence.push({ detail: `${use.count} use${use.count === 1 ? "" : "s"} observed` });
      return {
        id: "caps-observed-unapproved",
        severity: unapprovedSeverity(cap),
        package: name,
        version,
        message: `used ${cap} at runtime, which is not approved: ${against}`,
        evidence,
        docsUrl: findingDocsUrl("caps-observed-unapproved"),
      };
    });
}

/**
 * Compares observed capability use with the capability lockfile. Each observed
 * `name@version` is compared with its reference entry (the exact entry, else the
 * highest version of that name), as `check` does.
 */
export function compareObserved(observed: ObservedFile, caps: CapsLockfile, opts: CompareOptions = {}): CapsCheckReport {
  const reference = referenceIndex(caps);
  const results: PackageChangeResult[] = [];
  for (const [key, uses] of Object.entries(observed.packages)) {
    const parts = splitKey(key);
    if (parts === null) continue;
    const ref = reference(parts.name, parts.version);
    const findings = sortFindings(observedFindings(parts.name, parts.version, uses, ref));
    let result: PackageChangeResult = {
      kind: ref === null ? "added" : "updated",
      name: parts.name,
      ...(ref === null ? {} : { from: ref.version }),
      to: parts.version,
      lockfiles: [],
      findings,
      errors: [],
      risk: maxSeverity(findings),
    };
    if (opts.policy !== undefined) {
      const p = applyPolicy(result, opts.policy);
      result = { ...p, risk: p.listed?.list === "deny" ? "critical" : maxSeverity(p.findings) };
    }
    results.push(result);
  }
  const packages = results.filter((p) => p.findings.length > 0 || (p.allowedFindings?.length ?? 0) > 0 || p.listed?.list === "deny").toSorted(comparePackages);
  return {
    packages,
    findings: sortFindings(packages.flatMap((p) => p.findings)),
    risk: packages.map((p) => p.risk).toSorted(compareSeverity)[0] ?? "info",
    lockfiles: [],
    skipped: [],
    base: null,
    head: null,
    counts: {
      checked: results.length,
      unapproved: packages.filter((p) => p.findings.some((f) => f.id === "caps-observed-unapproved")).length,
    },
  };
}
