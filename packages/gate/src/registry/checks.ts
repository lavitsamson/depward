// Registry checks: metadata-only findings for one package request.
// Spec: docs/specs/gate.md §Registry checks. Finding catalog: docs/findings.md.
//
// Findings carry a severity only. Turning findings into allow / ask / deny, including
// the escalations (low-downloads + package-too-new → deny), is the policy engine's job
// (M2.4), so config overrides apply in one place.

import {
  DepwardError,
  escapeUnsafe,
  findingDocsUrl,
  isDeprecated,
  isDepwardError,
  publishTime,
  resolveVersion,
  sortFindings,
  type Finding,
  type Packument,
  type RegistryClient,
  type Severity,
  type VersionMeta,
} from "@depward/core";
import { loadGateData, type GateData } from "./data.ts";
import { addedMaintainers, provenanceDrop, publisherChange } from "./history.ts";

/** Thresholds for the age and popularity checks. Defaults follow the spec. */
export interface RegistryThresholds {
  /** `version-too-new` below this age. Default 7. */
  minVersionAgeDays?: number;
  /** `package-too-new` below this age. Default 30. */
  minPackageAgeDays?: number;
  /** `low-downloads` below this many weekly downloads. Default 500. */
  minWeeklyDownloads?: number;
  /** `maintainer-added-recently` looks back this many days. Default 30. */
  maintainerWindowDays?: number;
  /** `typosquat-suspect` needs the popular package to have this many times more downloads. Default 100. */
  typosquatRatio?: number;
}

/** Options for {@link checkRegistry}. */
export interface RegistryCheckOptions extends RegistryThresholds {
  registry: RegistryClient;
  /** Popular and hallucinated name lists. Default: the bundled data files. */
  data?: GateData;
  /** Clock, for tests. Default `Date.now`. */
  now?: () => number;
}

/** The package to check: a registry name and a range or dist-tag. */
export interface RegistryCheckInput {
  readonly name: string;
  /** Semver range, exact version, or dist-tag. `""` means `latest`. */
  readonly range: string;
}

/** Safer alternatives an agent can switch to. */
export interface Suggestion {
  /** A real package the name was probably meant to be. */
  name?: string;
  /** The newest version that passes `version-too-new`. */
  version?: string;
}

/** Result of {@link checkRegistry}. */
export interface RegistryCheckResult {
  readonly name: string;
  readonly range: string;
  /** The resolved version, or `null` if the package or version doesn't exist (or the lookup failed). */
  readonly version: string | null;
  readonly meta: VersionMeta | null;
  /** Sorted by severity, then package, then id. */
  readonly findings: Finding[];
  readonly suggestion: Suggestion;
  /** Weekly downloads; `null` when unknown (non-public registry, or the lookup failed). */
  readonly weeklyDownloads: number | null;
  /** Lookups that failed (network, timeout). The policy engine applies `onError` to these. */
  readonly errors: DepwardError[];
}

const DAY = 86_400_000;

function finding(id: string, severity: Severity, pkg: string, version: string | null, message: string, details: string[] = []): Finding {
  return {
    id,
    severity,
    package: pkg,
    ...(version === null ? {} : { version }),
    message,
    evidence: details.map((detail) => ({ detail })),
    docsUrl: findingDocsUrl(id),
  };
}

function toError(err: unknown): DepwardError {
  return isDepwardError(err) ? err : new DepwardError("INTERNAL", "registry check failed", { cause: err });
}

const plural = (n: number, unit: string): string => `${n} ${unit}${n === 1 ? "" : "s"}`;
const days = (ms: number): string => {
  const d = ms / DAY;
  return d < 1 ? plural(Math.max(0, Math.round(d * 24)), "hour") : plural(Math.floor(d), "day");
};

/** First publish of the package: `time.created`, else its earliest version. */
function createdAt(packument: Packument): number | null {
  const created = Date.parse(packument.time["created"] ?? "");
  if (Number.isFinite(created)) return created;
  let first: number | null = null;
  for (const v of Object.keys(packument.versions)) {
    const at = publishTime(packument, v);
    if (at !== null && (first === null || at < first)) first = at;
  }
  return first;
}

/**
 * Runs every registry check for one package. It never throws for registry or network
 * failures: those land in `errors`, alongside any findings already made.
 */
export async function checkRegistry(input: RegistryCheckInput, opts: RegistryCheckOptions): Promise<RegistryCheckResult> {
  const now = (opts.now ?? Date.now)();
  const minVersionAge = (opts.minVersionAgeDays ?? 7) * DAY;
  const minPackageAge = (opts.minPackageAgeDays ?? 30) * DAY;
  const minDownloads = opts.minWeeklyDownloads ?? 500;
  const ratio = opts.typosquatRatio ?? 100;
  const { name, range } = input;

  const findings: Finding[] = [];
  const errors: DepwardError[] = [];
  const suggestion: Suggestion = {};
  let version: string | null = null;
  let meta: VersionMeta | null = null;
  let weeklyDownloads: number | null = null;
  const done = (): RegistryCheckResult => ({
    name, range, version, meta, findings: sortFindings(findings), suggestion, weeklyDownloads, errors,
  });

  let data: GateData | null = opts.data ?? null;
  if (data === null) {
    try {
      data = await loadGateData();
    } catch (err) {
      errors.push(toError(err));
    }
  }

  const known = data?.hallucinated.get(name.toLowerCase());
  if (known) {
    suggestion.name = known.suggestion;
    findings.push(finding("known-hallucinated-name", "critical", name, null,
      `${name} is a package name AI models are documented to hallucinate. Did you mean ${known.suggestion}?`,
      [`first seen ${known.firstSeen}: ${known.source}`]));
  }

  // Fetch downloads alongside the packument; a 404 package costs one wasted request.
  const downloadsP = opts.registry.weeklyDownloads(name).then(
    (n) => ({ ok: true as const, n }),
    (err: unknown) => ({ ok: false as const, err }),
  );

  let packument: Packument | null;
  try {
    packument = await opts.registry.packument(name);
  } catch (err) {
    errors.push(toError(err));
    return done();
  }

  if (packument === null) {
    const similar = data?.popular.similar(name)[0];
    if (suggestion.name === undefined && similar) suggestion.name = similar.name;
    const hint = suggestion.name === undefined ? "" : ` Did you mean ${suggestion.name}?`;
    findings.push(finding("package-not-found", "high", name, null,
      `${name} does not exist on the registry. It may be a typo or a name an AI model made up.${hint}`));
    return done();
  }

  // Package-level checks.
  const created = createdAt(packument);
  if (created !== null && now - created < minPackageAge) {
    findings.push(finding("package-too-new", "medium", name, null,
      `${name} was first published ${days(now - created)} ago (minimum ${opts.minPackageAgeDays ?? 30} days).`,
      [`created ${new Date(created).toISOString()}`]));
  }

  const dl = await downloadsP;
  if (dl.ok) weeklyDownloads = dl.n;
  else errors.push(toError(dl.err));
  if (weeklyDownloads !== null && weeklyDownloads < minDownloads) {
    findings.push(finding("low-downloads", "medium", name, null,
      `${name} has ${weeklyDownloads} downloads in the last week (minimum ${minDownloads}).`));
  }

  // Unknown downloads (private registry, failed lookup) count as 0.
  if (data && data.popular.downloads(name) === undefined) {
    const floor = ratio * Math.max(weeklyDownloads ?? 0, 1);
    const targets = data.popular.similar(name).filter((p) => p.weeklyDownloads >= floor).slice(0, 3);
    const top = targets[0];
    if (top) {
      suggestion.name ??= top.name;
      const how = top.kind === "edit-distance" ? `${top.distance} character${top.distance === 1 ? "" : "s"} away from` : `a ${top.kind} swap of`;
      findings.push(finding("typosquat-suspect", "high", name, null,
        `${name} is ${how} the popular package ${top.name}, which has far more downloads. Did you mean ${top.name}?`,
        targets.map((t) => `${t.name}: ${t.weeklyDownloads} weekly downloads (${t.kind}, distance ${t.distance})`)));
    }
  }

  const added = addedMaintainers(packument, now, opts.maintainerWindowDays ?? 30);
  if (added.length > 0) {
    findings.push(finding("maintainer-added-recently", "low", name, null,
      `${name} gained ${added.length === 1 ? "a maintainer" : `${added.length} maintainers`} in the last ${opts.maintainerWindowDays ?? 30} days.`,
      added.slice(0, 10).map((a) => `${escapeUnsafe(a.name, 80)} first listed on ${a.version}`)));
  }

  // Version-level checks.
  meta = resolveVersion(packument, range);
  if (meta === null) {
    const tags = Object.entries(packument["dist-tags"]).slice(0, 10).map(([t, v]) => `${escapeUnsafe(t, 40)}: ${escapeUnsafe(v, 40)}`);
    findings.push(finding("version-not-found", "high", name, null,
      `No version of ${name} matches ${JSON.stringify(escapeUnsafe(range, 80))}.`, tags.length ? [`dist-tags: ${tags.join(", ")}`] : []));
    return done();
  }
  version = meta.version;

  const published = publishTime(packument, version);
  if (published !== null && now - published < minVersionAge) {
    const cutoff = now - minVersionAge;
    const inRange = resolveVersion(packument, range, { publishedBefore: cutoff });
    const older = inRange ?? resolveVersion(packument, "*", { publishedBefore: cutoff });
    if (older) suggestion.version = older.version;
    // A dist-tag (`latest`) names one version, so an older pick isn't "outside" anything.
    const isTag = Object.hasOwn(packument["dist-tags"], range.trim() === "" ? "latest" : range.trim());
    const label = inRange || isTag ? "" : " (outside the requested range)";
    const hint = older ? ` Use ${name}@${older.version}${label} instead.` : "";
    findings.push(finding("version-too-new", "medium", name, version,
      `${name}@${version} was published ${days(now - published)} ago (minimum ${opts.minVersionAgeDays ?? 7} days).${hint}`,
      [`published ${new Date(published).toISOString()}`]));
  }

  const pub = publisherChange(packument, meta);
  if (pub) {
    findings.push(finding("publisher-changed", "medium", name, version,
      `${name}@${version} was published by ${escapeUnsafe(pub.publisher, 80)}, who published none of the previous versions.`,
      [`previous publishers: ${pub.previous.map((p) => escapeUnsafe(p, 80)).join(", ")}`]));
  }

  const attested = provenanceDrop(packument, meta);
  if (attested) {
    findings.push(finding("provenance-dropped", "high", name, version,
      `${name}@${version} has no provenance attestation, but ${attested.version} did. It may not have been built by the usual CI.`));
  }

  if (isDeprecated(meta)) {
    findings.push(finding("deprecated", "low", name, version, `${name}@${version} is deprecated.`,
      [escapeUnsafe(meta.deprecated ?? "", 200)]));
  }

  return done();
}
