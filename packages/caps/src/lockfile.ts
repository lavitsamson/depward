// Reading and writing capabilities.lock.json. Spec: docs/specs/caps.md § Scan details.

import { DepwardError, escapeUnsafe } from "@depward/core";
import { compareVersions } from "@depward/diff";
import { CAPS_LOCKFILE_NAME, CAPS_LOCKFILE_VERSION, type CapsEntry, type CapsLockfile } from "./types.ts";

const CAPABILITY = /^[a-z][a-z0-9_]*$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TOP_FIELDS: ReadonlySet<string> = new Set(["version", "packages"]);
const ENTRY_FIELDS: ReadonlySet<string> = new Set(["capabilities", "approvedBy", "approvedAt", "reason"]);

/** Splits `name@version` (the name may be scoped). `null` when either part is empty. */
export function splitKey(key: string): { name: string; version: string } | null {
  const at = key.lastIndexOf("@");
  if (at <= 0 || at === key.length - 1) return null;
  const name = key.slice(0, at);
  if (name === "@" || (name.startsWith("@") && !name.includes("/"))) return null;
  return { name, version: key.slice(at + 1) };
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parseEntry(key: string, value: unknown, fail: (why: string) => never): CapsEntry {
  const where = escapeUnsafe(key, 200);
  if (!isRecord(value)) fail(`${where}: must be an object`);
  for (const field of Object.keys(value)) {
    if (!ENTRY_FIELDS.has(field)) fail(`${where}: unknown field ${JSON.stringify(escapeUnsafe(field, 100))}`);
  }
  const caps = value["capabilities"];
  if (!Array.isArray(caps)) fail(`${where}: capabilities must be an array`);
  const seen = new Set<string>();
  for (const cap of caps) {
    if (typeof cap !== "string" || !CAPABILITY.test(cap)) fail(`${where}: invalid capability ${JSON.stringify(escapeUnsafe(String(cap), 100))}`);
    if (seen.has(cap)) fail(`${where}: duplicate capability ${JSON.stringify(cap)}`);
    seen.add(cap);
  }
  const entry: CapsEntry = { capabilities: [...seen] };
  for (const field of ["approvedBy", "approvedAt", "reason"] as const) {
    const v = value[field];
    if (v === undefined) continue;
    if (typeof v !== "string") fail(`${where}: ${field} must be a string`);
    if (field === "approvedAt" && !DATE.test(v)) fail(`${where}: approvedAt must be a YYYY-MM-DD date`);
    entry[field] = v;
  }
  return entry;
}

/**
 * Parses and validates a capability lockfile.
 *
 * @param path Used in error messages. Default `capabilities.lock.json`.
 * @throws DepwardError `INVALID_LOCKFILE` for malformed JSON, an unsupported `version`,
 *   unknown fields, invalid keys, or invalid entries.
 */
export function parseCapsLockfile(text: string, path: string = CAPS_LOCKFILE_NAME): CapsLockfile {
  const fail = (why: string): never => {
    throw new DepwardError("INVALID_LOCKFILE", `${path}: ${why}`);
  };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new DepwardError("INVALID_LOCKFILE", `${path}: not valid JSON`, { cause: err });
  }
  if (!isRecord(doc)) return fail("must be a JSON object");
  for (const field of Object.keys(doc)) {
    if (!TOP_FIELDS.has(field)) fail(`unknown field ${JSON.stringify(escapeUnsafe(field, 100))}`);
  }
  if (doc["version"] !== CAPS_LOCKFILE_VERSION) fail(`unsupported version ${escapeUnsafe(JSON.stringify(doc["version"]) ?? "undefined", 50)}`);
  const packages = doc["packages"];
  if (!isRecord(packages)) return fail('"packages" must be an object');
  const out: Record<string, CapsEntry> = {};
  for (const [key, value] of Object.entries(packages)) {
    if (splitKey(key) === null) fail(`invalid package key ${JSON.stringify(escapeUnsafe(key, 200))}`);
    out[key] = parseEntry(key, value, fail);
  }
  return { version: CAPS_LOCKFILE_VERSION, packages: out };
}

/** Orders `name@version` keys by name, then by semver version. */
export function compareKeys(a: string, b: string): number {
  const x = splitKey(a);
  const y = splitKey(b);
  if (x === null || y === null) return a < b ? -1 : a > b ? 1 : 0;
  if (x.name !== y.name) return x.name < y.name ? -1 : 1;
  return compareVersions(x.version, y.version);
}

/**
 * Writes a capability lockfile deterministically: packages sorted by name then semver,
 * capabilities sorted, fields in the order `capabilities`, `approvedBy`, `approvedAt`,
 * `reason`; 2-space JSON with a trailing newline.
 */
export function serializeCapsLockfile(lock: CapsLockfile): string {
  const packages: Record<string, CapsEntry> = {};
  for (const key of Object.keys(lock.packages).toSorted(compareKeys)) {
    const e = lock.packages[key] as CapsEntry;
    packages[key] = {
      capabilities: [...e.capabilities].toSorted(),
      ...(e.approvedBy === undefined ? {} : { approvedBy: e.approvedBy }),
      ...(e.approvedAt === undefined ? {} : { approvedAt: e.approvedAt }),
      ...(e.reason === undefined ? {} : { reason: e.reason }),
    };
  }
  return `${JSON.stringify({ version: CAPS_LOCKFILE_VERSION, packages }, null, 2)}\n`;
}
