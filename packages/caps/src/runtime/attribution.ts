// Which package a file, URL, or stack frame belongs to: the innermost
// `node_modules/<name>` segment, keyed `name@version` with the version read from that
// directory's package.json (docs/specs/caps.md § Runtime details).
// https://nodejs.org/api/util.html#utilgetcallsitesframecount-options (Stability 1.1)

import { fileURLToPath } from "node:url";
import { getCallSites } from "node:util";
import { ErrorCaptureStackTrace, SafeMap } from "./intrinsics.ts";

/** A package directory found in a path. */
export interface PackageRef {
  name: string;
  /** The path or URL up to and including the package directory, with `/` separators. */
  root: string;
}

const NM = "/node_modules/";

/** The innermost package of a file path or `file:` URL. `null` for application code. */
export function packageOf(location: string): PackageRef | null {
  const s = location.replaceAll("\\", "/");
  const i = s.lastIndexOf(NM);
  if (i === -1) return null;
  const parts = s.slice(i + NM.length).split("/");
  const first = parts[0] ?? "";
  if (first === "" || first.startsWith(".")) return null;
  const scoped = first.startsWith("@") || first.toLowerCase().startsWith("%40");
  const raw = scoped ? `${first}/${parts[1] ?? ""}` : first;
  if (raw.endsWith("/")) return null;
  let name = raw;
  try {
    name = decodeURIComponent(raw);
  } catch {
    // Keep the raw segment.
  }
  return { name, root: s.slice(0, i + NM.length + raw.length) };
}

/** The file location of one line of an `Error.stack`, or `null`. */
export function stackLineLocation(line: string): string | null {
  const m = /\((.+):\d+:\d+\)$/.exec(line) ?? /^\s*at (?:async )?(.+):\d+:\d+$/.exec(line);
  return m?.[1] ?? null;
}

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
  const fold = process.platform === "win32" ? (s: string): string => s.replaceAll("\\", "/").toLowerCase() : (s: string): string => s.replaceAll("\\", "/");
  const selfRoots = opts.selfRoots.map(fold);
  const isSelf = (location: string): boolean => {
    const s = fold(location);
    return selfRoots.some((r) => s.startsWith(r));
  };

  const keyOf = (location: string): string | null => {
    const ref = packageOf(location);
    if (ref === null) return null;
    let key = versions.get(ref.root);
    if (key === undefined) {
      let version = "unknown";
      try {
        const dir = ref.root.startsWith("file:") ? fileURLToPath(`${ref.root}/`) : `${ref.root}/`;
        const v = (JSON.parse(opts.readFile(`${dir}package.json`)) as { version?: unknown }).version;
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
    if (file.startsWith("node:")) return skipInternal ? undefined : null;
    return keyOf(file);
  };

  const caller = (skipInternal = false): string | null => {
    if (useCallSites) {
      for (const site of getCallSites(16, { sourceMap: false })) {
        const d = decide(site.scriptName, skipInternal);
        if (d !== undefined) return d;
      }
      return null;
    }
    const holder: { stack?: string } = {};
    const limit = Error.stackTraceLimit;
    Error.stackTraceLimit = 16;
    ErrorCaptureStackTrace(holder);
    Error.stackTraceLimit = limit;
    for (const line of (holder.stack ?? "").split("\n").slice(1)) {
      const file = stackLineLocation(line);
      if (file === null) continue;
      const d = decide(file, skipInternal);
      if (d !== undefined) return d;
    }
    return null;
  };

  const site = (): string | null => {
    if (useCallSites) {
      for (const s of getCallSites(16, { sourceMap: false })) {
        if (s.scriptName === "" || s.scriptName.startsWith("node:") || isSelf(s.scriptName)) continue;
        return `${s.scriptName}:${s.lineNumber}:${s.columnNumber}`;
      }
      return null;
    }
    const holder: { stack?: string } = {};
    const limit = Error.stackTraceLimit;
    Error.stackTraceLimit = 16;
    ErrorCaptureStackTrace(holder);
    Error.stackTraceLimit = limit;
    for (const line of (holder.stack ?? "").split("\n").slice(1)) {
      const file = stackLineLocation(line);
      if (file === null || file.startsWith("node:") || isSelf(file)) continue;
      return /\((.+)\)$/.exec(line)?.[1] ?? line.trim().replace(/^at (?:async )?/, "");
    }
    return null;
  };

  return { keyOf, isSelf, caller, site };
}
