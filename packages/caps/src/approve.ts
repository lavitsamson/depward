// `depward caps approve`: record an approval for locked versions of a package.
// Spec: docs/specs/caps.md § Approve details.

import { CAPABILITIES } from "@depward/analyzer";
import { DepwardError, escapeUnsafe } from "@depward/core";
import { mapLimit } from "@depward/diff";
import { analyzeLocked, keyOf, readLocked, tarballOptions, type Located } from "./analyze.ts";
import { referenceIndex } from "./check.ts";
import { compareKeys } from "./lockfile.ts";
import { DEFAULT_SCAN_CONCURRENCY, utcDate } from "./scan.ts";
import { CAPS_LOCKFILE_VERSION, type CapsEntry, type CapsLockfile, type ScanOptions } from "./types.ts";

/** One `name[@version]` argument of `caps approve`. */
export interface ApproveTarget {
  name: string;
  /** Default: every locked registry version of `name`. */
  version?: string;
}

/** Options for {@link approveCapabilities}. */
export interface ApproveOptions extends Omit<ScanOptions, "existing" | "maxPackages"> {
  /** The current capability lockfile, or `null` to start a new one. */
  caps: CapsLockfile | null;
  targets: ApproveTarget[];
  /**
   * Approve only these capabilities (plus those of the reference entry the version still
   * uses). They needn't be detected statically. Default: every capability the version uses.
   */
  capabilities?: string[];
  /** Recorded as `approvedBy`. */
  by: string;
  /** Recorded as `reason`. */
  reason?: string;
}

/** One entry written by {@link approveCapabilities}. */
export interface ApprovedEntry {
  key: string;
  /** The approved capabilities. */
  capabilities: string[];
  /** Capabilities the version uses that stay unapproved (only with `capabilities`). */
  unapproved: string[];
  /**
   * Approved capabilities that static analysis doesn't see in the version. Runtime
   * enforcement can still observe them (dynamic `require`, computed property names).
   */
  notDetected: string[];
}

/** Result of {@link approveCapabilities}. Write `lockfile` only when `errors` is empty. */
export interface ApproveResult {
  lockfile: CapsLockfile;
  approved: ApprovedEntry[];
  errors: DepwardError[];
}

/** Parses `name`, `name@version`, `@scope/name` or `@scope/name@version`. */
export function parseTarget(arg: string): ApproveTarget {
  const at = arg.lastIndexOf("@");
  if (at > 0) return { name: arg.slice(0, at), version: arg.slice(at + 1) };
  return { name: arg };
}

/**
 * Analyzes the locked versions named by `opts.targets` and approves their capabilities
 * in a copy of `opts.caps`. Other entries are not touched.
 *
 * @throws DepwardError `INVALID_ARGUMENT` (unknown capability, or a target that is not
 *   locked as a registry package), plus the errors of reading the lockfiles.
 */
export async function approveCapabilities(opts: ApproveOptions): Promise<ApproveResult> {
  const known = new Set<string>(CAPABILITIES);
  for (const c of opts.capabilities ?? []) {
    if (!known.has(c)) throw new DepwardError("INVALID_ARGUMENT", `unknown capability ${JSON.stringify(escapeUnsafe(c, 50))}; known: ${CAPABILITIES.join(", ")}`);
  }
  const locked = await readLocked(opts.cwd);
  const chosen = new Map<string, Located>();
  for (const t of opts.targets) {
    const matches = [...locked.registry.entries()].filter(([, l]) => l.entry.name === t.name && (t.version === undefined || l.entry.version === t.version));
    if (matches.length === 0) {
      const what = escapeUnsafe(t.version === undefined ? t.name : keyOf({ name: t.name, version: t.version }), 214);
      throw new DepwardError("INVALID_ARGUMENT", `${what} is not locked as a registry package`);
    }
    for (const [key, l] of matches) chosen.set(key, l);
  }

  const keys = [...chosen.keys()].toSorted(compareKeys);
  const tarOpts = tarballOptions(opts);
  const analyses = await mapLimit(keys, opts.concurrency ?? DEFAULT_SCAN_CONCURRENCY, (k) => analyzeLocked(chosen.get(k) as Located, opts, tarOpts));

  const base: CapsLockfile = opts.caps ?? { version: CAPS_LOCKFILE_VERSION, packages: {} };
  const reference = referenceIndex(base);
  const packages: Record<string, CapsEntry> = { ...base.packages };
  const approved: ApprovedEntry[] = [];
  const errors: DepwardError[] = [];
  const today = utcDate((opts.now ?? Date.now)());
  keys.forEach((key, i) => {
    const a = analyses[i];
    const { entry } = chosen.get(key) as Located;
    if (a === undefined) return;
    if (!a.ok) {
      errors.push(a.error);
      return;
    }
    let caps = a.capabilities;
    if (opts.capabilities !== undefined) {
      // The reference entry's capabilities that the version still uses, plus the named
      // ones, even ones static analysis doesn't see (runtime enforcement may).
      const fromReference = (reference(entry.name, entry.version)?.entry.capabilities ?? []).filter((c) => a.capabilities.includes(c));
      caps = [...new Set([...fromReference, ...opts.capabilities])].toSorted();
    }
    packages[key] = {
      capabilities: caps,
      ...(caps.length === 0 ? {} : { approvedBy: opts.by, approvedAt: today }),
      ...(opts.reason === undefined ? {} : { reason: opts.reason }),
    };
    approved.push({ key, capabilities: caps, unapproved: a.capabilities.filter((c) => !caps.includes(c)), notDetected: caps.filter((c) => !a.capabilities.includes(c)) });
  });

  return { lockfile: { version: CAPS_LOCKFILE_VERSION, packages }, approved, errors };
}
