// The gate, end to end: package specs or a shell command in, a Decision out.
// Spec: docs/specs/gate.md §Flow and §Policy engine.

import {
  DepwardError,
  defaultConfig,
  escapeUnsafe,
  type DepwardConfig,
  type Finding,
  type PolicyAction,
} from "@depward/core";
import { checkPackage, type PackageCheckOptions } from "./check.ts";
import { nonRegistryFinding, parseInstallCommand } from "./command/analyze.ts";
import { parsePackageSpec, type SpecSource } from "./command/spec.ts";
import { strictest } from "./policy/actions.ts";
import { createPolicy, type DecidedFinding, type Policy } from "./policy/engine.ts";
import type { ListMatch } from "./policy/lists.ts";
import type { Suggestion } from "./registry/checks.ts";
import type { UpdateInfo } from "./update.ts";

/** Options for {@link checkSpecs} and {@link checkCommand}. */
export interface GateOptions extends Omit<PackageCheckOptions, "tarball" | "analyzeTarball"> {
  /** Default: {@link defaultConfig}. Its thresholds apply unless set explicitly here. */
  config?: DepwardConfig;
  /** A policy compiled from `config`, to reuse across calls. */
  policy?: Policy;
  /** Packages checked at the same time. Default 4. */
  concurrency?: number;
}

/** The decision for one requested package. */
export interface PackageDecision {
  readonly name: string;
  /** The requested range or tag; for non-registry specs, the spec as written. */
  readonly range: string;
  readonly source: SpecSource;
  /** The resolved version, or `null` (not found, not checked, or the lookup failed). */
  readonly version: string | null;
  readonly action: PolicyAction;
  readonly findings: DecidedFinding[];
  /** Failed lookups (network, timeout, offline). They cost `errorAction`. */
  readonly errors: DepwardError[];
  readonly errorAction: PolicyAction | null;
  readonly listed: ListMatch | null;
  readonly suggestion: Suggestion;
  readonly weeklyDownloads: number | null;
  /** Whether the tarball was downloaded and analyzed. */
  readonly analyzed: boolean;
  /**
   * The locked version this request was diffed against (the update path), or `null`
   * when it wasn't an update or no `diffUpdate` was given.
   */
  readonly update: UpdateInfo | null;
}

/** The gate's answer for a whole command or list of specs. */
export interface Decision {
  /** The strictest action among the packages and the command-level findings. */
  readonly action: PolicyAction;
  readonly packages: PackageDecision[];
  /** Findings about the command that belong to no package (`unparseable-command`). */
  readonly findings: DecidedFinding[];
  /** One readable line per cause of a non-`allow` action, strictest first. */
  readonly reasons: string[];
}

interface Request {
  readonly name: string;
  readonly range: string;
  readonly source: SpecSource;
  findings: Finding[];
}

async function pool<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
}

async function decideRequest(req: Request, policy: Policy, opts: GateOptions): Promise<PackageDecision> {
  const base = { name: req.name, range: req.range, source: req.source };
  // Nothing on the registry to look up, or a deny entry that holds for every version.
  if (req.source !== "registry" || policy.deniedByName(req.name) !== null) {
    const verdict = policy.decidePackage({ name: req.name, version: null, findings: req.findings, errors: [] });
    return { ...base, version: null, ...verdict, errors: [], suggestion: {}, weeklyDownloads: null, analyzed: false, update: null };
  }

  const { config: _c, policy: _p, concurrency: _n, ...checkOpts } = opts;
  const result = await checkPackage({ name: req.name, range: req.range }, {
    ...policy.config.thresholds,
    ...checkOpts,
    // The tarball can't change the outcome of a denied or allow-listed package.
    analyzeTarball: (r) => {
      const v = policy.decidePackage({ name: r.name, version: r.version, findings: [...req.findings, ...r.findings], errors: r.errors });
      return v.action !== "deny" && v.listed?.list !== "allow";
    },
  });
  const verdict = policy.decidePackage({
    name: req.name, version: result.version, findings: [...req.findings, ...result.findings], errors: result.errors,
  });
  return {
    ...base,
    version: result.version,
    ...verdict,
    errors: result.errors,
    suggestion: result.suggestion,
    weeklyDownloads: result.weeklyDownloads,
    analyzed: result.profile !== null,
    update: result.update,
  };
}

const clean = (s: string): string => escapeUnsafe(s, 200);

function reasonsFor(packages: readonly PackageDecision[], findings: readonly DecidedFinding[]): string[] {
  const lines: { action: PolicyAction; text: string }[] = [];
  for (const p of packages) {
    const label = clean(
      p.version === null ? (p.source === "registry" ? `${p.name}@${p.range}` : p.name)
      : p.update === null ? `${p.name}@${p.version}`
      : `${p.name}@${p.version} (update from ${p.update.from})`,
    );
    for (const d of p.findings) {
      if (d.action !== "allow") lines.push({ action: d.action, text: `${d.action} ${label}: ${d.finding.id} — ${clean(d.finding.message)}` });
    }
    if (p.errorAction !== null && p.errorAction !== "allow") {
      const codes = [...new Set(p.errors.map((e) => e.code))].join(", ");
      lines.push({ action: p.errorAction, text: `${p.errorAction} ${label}: lookup failed (${codes}); onError is ${p.errorAction}` });
    }
  }
  for (const d of findings) {
    if (d.action !== "allow") lines.push({ action: d.action, text: `${d.action} ${d.finding.id} — ${clean(d.finding.message)}` });
  }
  const rank = { deny: 0, ask: 1, allow: 2 } as const;
  return lines.toSorted((a, b) => rank[a.action] - rank[b.action]).map((l) => l.text);
}

async function decide(requests: Request[], stray: readonly Finding[], opts: GateOptions): Promise<Decision> {
  const policy = opts.policy ?? createPolicy(opts.config ?? defaultConfig());
  const packages = await pool(requests, opts.concurrency ?? 4, (r) => decideRequest(r, policy, opts));
  const findings = policy.decideFindings(stray);
  const action = strictest([...packages.map((p) => p.action), ...findings.map((d) => d.action)]);
  return { action, packages, findings, reasons: reasonsFor(packages, findings) };
}

/** Merges duplicate requests and attaches each package's own findings to it. */
function group(entries: readonly Omit<Request, "findings">[], findings: readonly Finding[]): { requests: Request[]; stray: Finding[] } {
  const requests: Request[] = [];
  const seen = new Set<string>();
  for (const e of entries) {
    const key = `${e.source}\0${e.name}\0${e.range}`;
    if (seen.has(key)) continue;
    seen.add(key);
    requests.push({ ...e, findings: [] });
  }
  const stray: Finding[] = [];
  for (const f of findings) {
    const owner = requests.find((r) => r.name === f.package);
    if (owner) owner.findings.push(f);
    else stray.push(f);
  }
  return { requests, stray };
}

/**
 * Checks package specs as written for `npm install` (`left-pad@1.3.0`, `@scope/x`,
 * `alias@npm:real@^1`, git and file specs) and decides allow / ask / deny.
 * Lookup failures never throw; they cost `onError`.
 *
 * @throws DepwardError `INVALID_ARGUMENT` for a spec that isn't a package spec
 * @throws DepwardError `INVALID_CONFIG` for malformed `allow` / `deny` entries
 */
export async function checkSpecs(specs: readonly string[], opts: GateOptions): Promise<Decision> {
  const entries: Omit<Request, "findings">[] = [];
  const findings: Finding[] = [];
  for (const raw of specs) {
    const spec = parsePackageSpec(raw);
    if (spec.source === "invalid") throw new DepwardError("INVALID_ARGUMENT", `${JSON.stringify(escapeUnsafe(raw, 200))}: ${spec.reason}`);
    if (spec.source === "registry") {
      entries.push({ name: spec.name, range: spec.range, source: "registry" });
      continue;
    }
    entries.push({ name: spec.alias ?? raw, range: raw, source: spec.source });
    if (spec.source !== "workspace") findings.push(nonRegistryFinding(spec, raw));
  }
  const { requests, stray } = group(entries, findings);
  return decide(requests, stray, opts);
}

/**
 * Tokenizes a shell command, finds what it would install or run, and decides
 * allow / ask / deny. Commands without a package-manager install are allowed without
 * any network access.
 *
 * @throws DepwardError `INVALID_CONFIG` for malformed `allow` / `deny` entries
 */
export async function checkCommand(command: string, opts: GateOptions): Promise<Decision> {
  const analysis = parseInstallCommand(command);
  const { requests, stray } = group(analysis.requests.map((r) => ({ name: r.name, range: r.range, source: r.source })), analysis.findings);
  return decide(requests, stray, opts);
}
