// Observed capability use, and the `.depward/caps-observed.json` format.
// Spec: docs/specs/caps.md § Runtime details. Pure except `writeObserved`, which takes
// its file functions as arguments (the real fs, captured at startup).

import { SafeMap } from "./intrinsics.ts";

/** Version of the observed-file format. */
export const OBSERVED_VERSION = 1;
/** Members kept per capability. */
export const MAX_MEMBERS = 50;

/** One capability of one package in the observed file. */
export interface ObservedUse {
  count: number;
  /** What was used, for example `fs.readFileSync` or `process.env.NPM_TOKEN`. Sorted. */
  members: string[];
}

/** The observed file: `packages["name@version"][capability]`. */
export interface ObservedFile {
  version: typeof OBSERVED_VERSION;
  packages: Record<string, Record<string, ObservedUse>>;
}

/** A counter bumped by a wrapper on each call. */
export interface UseRecord {
  readonly key: string;
  readonly cap: string;
  readonly member: string;
  count: number;
}

/** In-memory records, one per (package, capability, member). */
export interface Store {
  /** The record for one member; wrappers keep it and bump `count`. */
  record(key: string, cap: string, member: string): UseRecord;
  /** What was observed so far, as an observed file (packages without uses left out). */
  snapshot(): ObservedFile;
}

export function createStore(): Store {
  const records = new SafeMap<string, UseRecord>();
  return {
    record(key, cap, member) {
      const id = `${key}\0${cap}\0${member}`;
      let r = records.get(id);
      if (r === undefined) {
        r = { key, cap, member, count: 0 };
        records.set(id, r);
      }
      return r;
    },
    snapshot() {
      const file: ObservedFile = { version: OBSERVED_VERSION, packages: {} };
      for (const r of records.values()) {
        if (r.count === 0) continue;
        const pkg = (file.packages[r.key] ??= {});
        const use = (pkg[r.cap] ??= { count: 0, members: [] });
        use.count += r.count;
        if (!use.members.includes(r.member)) use.members.push(r.member);
      }
      return normalizeObserved(file);
    },
  };
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Parses an observed file. Returns `null` for anything malformed (the caller decides
 * whether that is an error).
 */
export function parseObserved(text: string): ObservedFile | null {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(doc) || doc["version"] !== OBSERVED_VERSION || !isRecord(doc["packages"])) return null;
  const out: ObservedFile = { version: OBSERVED_VERSION, packages: {} };
  for (const [key, caps] of Object.entries(doc["packages"])) {
    if (!isRecord(caps)) return null;
    const pkg: Record<string, ObservedUse> = {};
    for (const [cap, use] of Object.entries(caps)) {
      if (!isRecord(use) || typeof use["count"] !== "number" || !Number.isInteger(use["count"]) || use["count"] < 0) return null;
      const members = use["members"];
      if (!Array.isArray(members) || !members.every((m) => typeof m === "string")) return null;
      pkg[cap] = { count: use["count"], members: members as string[] };
    }
    out.packages[key] = pkg;
  }
  return out;
}

/** Adds `b` to `a`: counts add up, members are unioned (capped). Pure. */
export function mergeObserved(a: ObservedFile, b: ObservedFile): ObservedFile {
  const out: ObservedFile = { version: OBSERVED_VERSION, packages: {} };
  for (const file of [a, b]) {
    for (const [key, caps] of Object.entries(file.packages)) {
      const pkg = (out.packages[key] ??= {});
      for (const [cap, use] of Object.entries(caps)) {
        const into = (pkg[cap] ??= { count: 0, members: [] });
        into.count += use.count;
        for (const m of use.members) if (!into.members.includes(m)) into.members.push(m);
      }
    }
  }
  return normalizeObserved(out);
}

/** Sorts keys and members and caps the member lists, for deterministic output. */
export function normalizeObserved(file: ObservedFile): ObservedFile {
  const packages: ObservedFile["packages"] = {};
  for (const key of Object.keys(file.packages).toSorted()) {
    const caps = file.packages[key] ?? {};
    const pkg: Record<string, ObservedUse> = {};
    for (const cap of Object.keys(caps).toSorted()) {
      const use = caps[cap] as ObservedUse;
      pkg[cap] = { count: use.count, members: [...use.members].toSorted().slice(0, MAX_MEMBERS) };
    }
    packages[key] = pkg;
  }
  return { version: OBSERVED_VERSION, packages };
}

/** File functions {@link writeObserved} needs. */
export interface ObservedIo {
  readFile(path: string): string;
  writeFile(path: string, text: string): void;
  rename(from: string, to: string): void;
  mkdir(dir: string): void;
}

/**
 * Merges `observed` into the file at `path` (a malformed existing file is replaced) and
 * writes it through a temporary file. Does nothing when nothing was observed.
 */
export function writeObserved(path: string, dir: string, observed: ObservedFile, io: ObservedIo): void {
  if (Object.keys(observed.packages).length === 0) return;
  let previous: ObservedFile | null = null;
  try {
    previous = parseObserved(io.readFile(path));
  } catch {
    previous = null;
  }
  const merged = previous === null ? observed : mergeObserved(previous, observed);
  io.mkdir(dir);
  const tmp = `${path}.${process.pid}.tmp`;
  io.writeFile(tmp, `${JSON.stringify(merged, null, 2)}\n`);
  io.rename(tmp, path);
}
