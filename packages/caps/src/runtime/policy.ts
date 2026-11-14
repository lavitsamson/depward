// Enforce mode's policy: what capabilities.lock.json approves, with the same reference
// rule as `depward caps check` (the exact name@version entry, else the highest version
// of that name). A minimal reader, because the runtime can't import the main package.

import { DepwardCapabilityError } from "./errors.ts";
import { SafeMap, SafeSet, StringLastIndexOf, StringSlice } from "./intrinsics.ts";

const NUMS = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/;

/** Same ordering as @depward/diff's compareVersions. */
export function compareVersions(a: string, b: string): number {
  const x = NUMS.exec(a);
  const y = NUMS.exec(b);
  if (!x || !y) return x ? 1 : y ? -1 : a < b ? -1 : a > b ? 1 : 0;
  for (let i = 1; i <= 3; i++) {
    const d = Number(x[i]) - Number(y[i]);
    if (d !== 0) return d;
  }
  const pa = x[4];
  const pb = y[4];
  if (pa === pb) return 0;
  if (pa === undefined) return 1;
  if (pb === undefined) return -1;
  return pa < pb ? -1 : 1;
}

/** `name@version` → its parts. Uses captured string methods: it runs on every new use record. */
function split(key: string): { name: string; version: string } | null {
  const at = StringLastIndexOf(key, "@");
  if (at <= 0 || at === key.length - 1) return null;
  return { name: StringSlice(key, 0, at), version: StringSlice(key, at + 1) };
}

/** What a package may do at runtime. */
export interface RuntimePolicy {
  /** Whether package `key` (`name@version`) may use `cap`. */
  allows(key: string, cap: string): boolean;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Builds the policy from the text of capabilities.lock.json.
 *
 * @throws DepwardCapabilityError `CAPS_POLICY` when the text is not a version 1
 *   capability lockfile.
 */
export function parsePolicy(text: string, path: string): RuntimePolicy {
  const fail = (why: string): never => {
    throw new DepwardCapabilityError("CAPS_POLICY", `enforce mode can't use ${path}: ${why}`);
  };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return fail("not valid JSON");
  }
  if (!isRecord(doc) || doc["version"] !== 1 || !isRecord(doc["packages"])) return fail("not a version 1 capability lockfile");
  // This runs at startup, before package code. `allows` runs later, while packages may
  // have replaced Map, Set, or String methods, so it only uses the Safe* copies.
  const exact = new SafeMap<string, SafeSet<string>>();
  const latest = new SafeMap<string, { version: string; caps: SafeSet<string> }>();
  for (const [key, entry] of Object.entries(doc["packages"])) {
    const parts = split(key);
    const caps = isRecord(entry) ? entry["capabilities"] : undefined;
    if (parts === null || !Array.isArray(caps) || !caps.every((c) => typeof c === "string")) return fail(`invalid entry ${JSON.stringify(key)}`);
    const set = new SafeSet<string>();
    for (const c of caps as string[]) set.add(c);
    exact.set(key, set);
    const seen = latest.get(parts.name);
    if (seen === undefined || compareVersions(parts.version, seen.version) > 0) latest.set(parts.name, { version: parts.version, caps: set });
  }
  return {
    allows(key, cap) {
      let caps = exact.get(key);
      if (caps === undefined) {
        const parts = split(key);
        caps = latest.get(parts === null ? key : parts.name)?.caps;
      }
      return caps === undefined ? false : caps.has(cap);
    },
  };
}
