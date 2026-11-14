// Which package a file, URL, or stack frame belongs to: the innermost
// `node_modules/<name>` segment, keyed `name@version` with the version read from that
// directory's package.json (docs/specs/caps.md § Runtime details).
// https://nodejs.org/api/util.html#utilgetcallsitesframecount-options (Stability 1.1)

//
// Attribution decides who is calling, so it runs while package code may have replaced
// built-ins: it uses only the captured intrinsics, index loops, and copies of the Node
// functions taken at load (named imports are live bindings that
// module.syncBuiltinESMExports() would update after a package patches the module).

import * as nodeUrl from "node:url";
import * as nodeUtil from "node:util";
import {
  DecodeURIComponent,
  ErrorCaptureStackTrace,
  JSONParse,
  ObjectHasOwn,
  RegExpExec,
  SafeMap,
  StringEndsWith,
  StringIndexOf,
  StringLastIndexOf,
  StringSlice,
  StringStartsWith,
  StringToLowerCase,
  toSlashes,
} from "./intrinsics.ts";

const fileURLToPath: typeof nodeUrl.fileURLToPath = nodeUrl.fileURLToPath;
const getCallSites: typeof nodeUtil.getCallSites = nodeUtil.getCallSites;

/** A package directory found in a path. */
export interface PackageRef {
  name: string;
  /** The path or URL up to and including the package directory, with `/` separators. */
  root: string;
}

const NM = "/node_modules/";

/** The innermost package of a file path or `file:` URL. `null` for application code. */
/** The text of `s` from `from` up to the next `/` (or the end). */
function segment(s: string, from: number): string {
  const end = StringIndexOf(s, "/", from);
  return end === -1 ? StringSlice(s, from) : StringSlice(s, from, end);
}

export function packageOf(location: string): PackageRef | null {
  const s = toSlashes(location);
  const i = StringLastIndexOf(s, NM);
  if (i === -1) return null;
  const start = i + NM.length;
  const first = segment(s, start);
  if (first === "" || StringStartsWith(first, ".")) return null;
  const scoped = StringStartsWith(first, "@") || StringStartsWith(StringToLowerCase(first), "%40");
  const second = scoped && start + first.length < s.length ? segment(s, start + first.length + 1) : "";
  const raw = scoped ? `${first}/${second}` : first;
  if (StringEndsWith(raw, "/")) return null;
  let name = raw;
  try {
    name = DecodeURIComponent(raw);
  } catch {
    // Keep the raw segment.
  }
  return { name, root: StringSlice(s, 0, start + raw.length) };
}

const PAREN_LOCATION = /\((.+):\d+:\d+\)$/;
const BARE_LOCATION = /^\s*at (?:async )?(.+):\d+:\d+$/;

/** The file location of one line of an `Error.stack`, or `null`. */
export function stackLineLocation(line: string): string | null {
  const m = RegExpExec(PAREN_LOCATION, line) ?? RegExpExec(BARE_LOCATION, line);
  return m === null ? null : (m[1] ?? null);
}

const PAREN = /\((.+)\)$/;

/** Options for {@link createAttribution}. */
export interface AttributionOptions {
  /** URL or path prefix of the caps package itself: never attributed, skipped in stacks. */
  selfRoots: readonly string[];
  /** Reads a package.json (the real `fs.readFileSync`, captured at startup). */
  readFile: (path: string) => string;
}

/** Package attribution with a per-directory version cache. */
export interface Attribution {
  /** `name@version` of the package containing `location`, or `null`. */
  keyOf(location: string): string | null;
  /** True when `location` is inside the caps package. */
  isSelf(location: string): boolean;
  /**
   * `name@version` of the package whose code called into the current wrapper: the first
   * stack frame with a location outside the caps package. When that frame is Node's own
   * code, Node made the access and the result is `null`, unless `skipInternal` (used for
   * `process.dlopen`, which Node's loader calls on a package's behalf).
   */
  caller(skipInternal?: boolean): string | null;
  /** `file:line:column` of the first stack frame outside the caps package and Node, or `null`. */
  site(): string | null;
}

/** Creates the attribution used by the hooks and the global wrappers. */
export function createAttribution(opts: AttributionOptions): Attribution {
  const versions = new SafeMap<string, string>();
  // Windows paths and file URLs compare case-insensitively (drive letters vary).
  const fold = process.platform === "win32" ? (s: string): string => StringToLowerCase(toSlashes(s)) : toSlashes;
  const selfRoots = opts.selfRoots.map(fold);
  const readFile = opts.readFile;
  const isSelf = (location: string): boolean => {
    const s = fold(location);
    for (let i = 0; i < selfRoots.length; i++) if (StringStartsWith(s, selfRoots[i] as string)) return true;
    return false;
  };

  const keyOf = (location: string): string | null => {
    const ref = packageOf(location);
    if (ref === null) return null;
    let key = versions.get(ref.root);
    if (key === undefined) {
      let version = "unknown";
      try {
        const dir = StringStartsWith(ref.root, "file:") ? fileURLToPath(`${ref.root}/`) : `${ref.root}/`;
        const pkg: unknown = JSONParse(readFile(`${dir}package.json`));
        const v = typeof pkg === "object" && pkg !== null && ObjectHasOwn(pkg, "version") ? (pkg as { version: unknown }).version : undefined;
        if (typeof v === "string" && v !== "") version = v;
      } catch {
        // Unreadable or missing package.json: keep "unknown".
      }
      key = `${ref.name}@${version}`;
      versions.set(ref.root, key);
    }
    return key;
  };

  // getCallSites with `sourceMap: false`, so `--enable-source-maps` can't move a frame
  // out of node_modules. Fall back to Error.stack where the option isn't supported.
  let useCallSites = true;
  try {
    getCallSites(1, { sourceMap: false });
  } catch {
    useCallSites = false;
  }

  const decide = (file: string, skipInternal: boolean): string | null | undefined => {
    if (file === "" || isSelf(file)) return undefined;
    if (StringStartsWith(file, "node:")) return skipInternal ? undefined : null;
    return keyOf(file);
  };

  /**
   * Calls `visit(file, location)` for each stack frame, innermost first, until it
   * returns something other than `undefined`. No arrays are built: their index setters
   * and methods can be replaced.
   */
  const eachFrame = <T>(visit: (file: string, location: string) => T | undefined): T | undefined => {
    if (useCallSites) {
      const sites = getCallSites(16, { sourceMap: false });
      for (let i = 0; i < sites.length; i++) {
        const s = sites[i] as nodeUtil.CallSiteObject;
        const r = visit(s.scriptName, `${s.scriptName}:${s.lineNumber}:${s.columnNumber}`);
        if (r !== undefined) return r;
      }
      return undefined;
    }
    const holder: { stack?: string } = {};
    const limit = Error.stackTraceLimit;
    Error.stackTraceLimit = 16;
    ErrorCaptureStackTrace(holder);
    Error.stackTraceLimit = limit;
    const stack = typeof holder.stack === "string" ? holder.stack : "";
    // Skip the first line (the message).
    for (let at = StringIndexOf(stack, "\n"); at !== -1; ) {
      const next = StringIndexOf(stack, "\n", at + 1);
      const line = next === -1 ? StringSlice(stack, at + 1) : StringSlice(stack, at + 1, next);
      at = next;
      const file = stackLineLocation(line);
      if (file === null) continue;
      const r = visit(file, RegExpExec(PAREN, line)?.[1] ?? line);
      if (r !== undefined) return r;
    }
    return undefined;
  };

  const caller = (skipInternal = false): string | null => eachFrame((file) => decide(file, skipInternal)) ?? null;

  const site = (): string | null =>
    eachFrame((file, location) => (file === "" || StringStartsWith(file, "node:") || isSelf(file) ? undefined : location)) ?? null;

  return { keyOf, isSelf, caller, site };
}
