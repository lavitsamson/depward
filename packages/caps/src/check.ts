// `depward caps check`: fail CI when a locked version uses a capability that nobody
// approved. Spec: docs/specs/caps.md § Check details. The report is diff's DiffView, so
// every diff renderer (terminal, JSON, Markdown, SARIF) works unchanged.

import { compareSeverity, escapeUnsafe, findingDocsUrl, sortFindings, type Evidence, type Finding, type Severity } from "@depward/core";
import type { Capability, PackageProfile } from "@depward/analyzer";
import {
  HIGH_RISK_CAPABILITIES,
  MAX_EVIDENCE,
  applyPolicy,
  lockfileLocator,
  mapLimit,
  nonRegistryResult,
  reachesFailOn,
  type DiffView,
  type FailOn,
  type PackageChangeResult,
} from "@depward/diff";
import type { Policy } from "@depward/gate";
import { analyzeLocked, enforceLimit, keyOf, readLocked, tarballOptions, type Located } from "./analyze.ts";
import { compareKeys, splitKey } from "./lockfile.ts";
import { DEFAULT_SCAN_CONCURRENCY, DEFAULT_SCAN_MAX_PACKAGES } from "./scan.ts";
import type { CapsEntry, CapsLockfile, ScanOptions } from "./types.ts";

/** Finding IDs emitted by `caps check`. Stable public API (docs/findings.md). */
export const CAPS_FINDING_IDS: readonly string[] = ["caps-unapproved"];

/** Options for {@link checkCapabilities}. */
export interface CheckOptions extends Omit<ScanOptions, "existing" | "now"> {
  /** The committed capability lockfile. */
  caps: CapsLockfile;
  /** The project's policy (`createPolicy(config)`), applied as in `diff`. Default: none. */
  policy?: Policy;
}

/** Result of {@link checkCapabilities}: a diff view plus counts. */
export interface CapsCheckReport extends DiffView {
  counts: {
    /** Registry entries checked. */
    checked: number;
    /** Packages with at least one counted `caps-unapproved` finding. */
    unapproved: number;
  };
}

/** The entry a locked version is compared with. */
export interface CapsReference {
  key: string;
  version: string;
  entry: CapsEntry;
}

/** Indexes a capability lockfile by package name. */
export function referenceIndex(caps: CapsLockfile): (name: string, version: string) => CapsReference | null {
  const byName = new Map<string, string[]>();
  for (const key of Object.keys(caps.packages)) {
    const parts = splitKey(key);
    if (parts === null) continue;
    byName.set(parts.name, [...(byName.get(parts.name) ?? []), key]);
  }
  for (const keys of byName.values()) keys.sort(compareKeys);
  return (name, version) => {
    const exact = `${name}@${version}`;
    const key = caps.packages[exact] !== undefined ? exact : byName.get(name)?.at(-1);
    if (key === undefined) return null;
    return { key, version: splitKey(key)?.version ?? version, entry: caps.packages[key] as CapsEntry };
  };
}

function evidenceFor(profile: PackageProfile, cap: string): Evidence[] {
  const uses = profile.capabilities[cap as Capability] ?? [];
  const evidence: Evidence[] = uses.map((u) => ({ file: u.file, ...(u.line === undefined ? {} : { line: u.line }), snippet: u.evidence }));
  return evidence.length <= MAX_EVIDENCE ? evidence : [...evidence.slice(0, MAX_EVIDENCE), { detail: `and ${evidence.length - MAX_EVIDENCE} more` }];
}

/** `caps-unapproved` findings for the capabilities `reference` doesn't list. */
export function unapprovedFindings(name: string, version: string, profile: PackageProfile, capabilities: readonly string[], reference: CapsReference | null): Finding[] {
  const approved = new Set(reference?.entry.capabilities ?? []);
  const against =
    reference === null
      ? `${escapeUnsafe(name, 214)} has no entry in the capability lockfile`
      : reference.version === version
        ? "its entry in the capability lockfile does not list it"
        : `the approved entry for ${escapeUnsafe(reference.version, 64)} does not list it`;
  return capabilities
    .filter((c) => !approved.has(c))
    .map((c) => ({
      id: "caps-unapproved",
      severity: (HIGH_RISK_CAPABILITIES.has(c as Capability) ? "high" : "medium") as Severity,
      package: name,
      version,
      message: `uses ${c}, which is not approved: ${against}`,
      evidence: evidenceFor(profile, c),
      docsUrl: findingDocsUrl("caps-unapproved"),
    }));
}

const maxSeverity = (fs: readonly Finding[]): Severity => fs.map((f) => f.severity).toSorted(compareSeverity)[0] ?? "info";

function comparePackages(a: PackageChangeResult, b: PackageChangeResult): number {
  return compareSeverity(a.risk, b.risk) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || compareKeys(keyOf({ name: a.name, version: a.to }), keyOf({ name: b.name, version: b.to }));
}

const UNVERIFIABLE: ReadonlySet<string> = new Set(["git", "tarball", "other"]);

/**
 * Checks every registry entry of the lockfiles in `opts.cwd` against the capability
 * lockfile: each capability a version uses must be listed by its reference entry (the
 * exact `name@version`, else the highest version of that name).
 *
 * @throws DepwardError `NOT_FOUND` (no lockfile), `INVALID_LOCKFILE`, `LIMIT_EXCEEDED`.
 */
export async function checkCapabilities(opts: CheckOptions): Promise<CapsCheckReport> {
  const locked = await readLocked(opts.cwd);
  enforceLimit(locked, opts.maxPackages ?? DEFAULT_SCAN_MAX_PACKAGES);
  const locators = new Map(locked.lockfiles.map((l) => [l.path, lockfileLocator(l.text)]));
  const reference = referenceIndex(opts.caps);
  const tarOpts = tarballOptions(opts);

  const keys = [...locked.registry.keys()].toSorted(compareKeys);
  const results = await mapLimit(keys, opts.concurrency ?? DEFAULT_SCAN_CONCURRENCY, async (key): Promise<PackageChangeResult> => {
    const { entry, lockfiles } = locked.registry.get(key) as Located;
    const ref = reference(entry.name, entry.version);
    const line = locators.get(lockfiles[0] ?? "")?.(entry.name, entry.version);
    const result: PackageChangeResult = {
      kind: ref === null ? "added" : "updated",
      name: entry.name,
      ...(ref === null ? {} : { from: ref.version }),
      to: entry.version,
      lockfiles,
      ...(line === undefined ? {} : { line }),
      findings: [],
      errors: [],
      risk: "info",
    };
    const analysis = await analyzeLocked({ entry, lockfiles }, opts, tarOpts);
    if (analysis.ok) result.findings = sortFindings(unapprovedFindings(entry.name, entry.version, analysis.profile, analysis.capabilities, ref));
    else if (analysis.finding !== null) result.findings = [analysis.finding];
    else result.errors.push(analysis.error);
    result.risk = maxSeverity(result.findings);
    return result;
  });

  const external = [...locked.other.values()].filter((o) => UNVERIFIABLE.has(o.source)).map((o) => nonRegistryResult(o.entry, o.lockfiles[0] ?? ""));
  const skipped = [...locked.other.values()].filter((o) => !UNVERIFIABLE.has(o.source)).map((o) => o.key).toSorted(compareKeys);

  const policy = opts.policy;
  // applyPolicy's risk follows diff's escalation for updates; caps findings use plain
  // severity (critical only for a deny-listed package).
  const all = [...results, ...external].map((r) => {
    if (policy === undefined) return r;
    const p = applyPolicy(r, policy);
    return { ...p, risk: p.listed?.list === "deny" ? "critical" : maxSeverity(p.findings) } satisfies PackageChangeResult;
  });
  const packages = all.filter((p) => p.findings.length > 0 || p.errors.length > 0 || (p.allowedFindings?.length ?? 0) > 0 || p.listed?.list === "deny").toSorted(comparePackages);
  return {
    packages,
    findings: sortFindings(packages.flatMap((p) => p.findings)),
    risk: packages.map((p) => p.risk).toSorted(compareSeverity)[0] ?? "info",
    lockfiles: locked.lockfiles.map((l) => ({ path: l.path, format: l.format, counts: { added: 0, removed: 0, changed: 0 }, findings: [] })),
    skipped,
    base: null,
    head: null,
    counts: { checked: keys.length, unapproved: packages.filter((p) => p.findings.some((f) => f.id === "caps-unapproved")).length },
  };
}

/**
 * The exit code of `caps check`: 20 when an unapproved capability counts or a package's
 * risk reaches `failOn`, else 1 when a package could not be checked, else 0.
 */
export function capsCheckExitCode(report: CapsCheckReport, failOn: FailOn): 0 | 1 | 20 {
  if (report.counts.unapproved > 0 || reachesFailOn(report.packages, failOn)) return 20;
  return report.packages.some((p) => p.errors.length > 0) ? 1 : 0;
}
