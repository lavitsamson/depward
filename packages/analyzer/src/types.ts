import type { Evidence, Severity } from "@depward/core";

/** What a package's code can do. See `docs/specs/analyzer.md` § Capability rules. */
export type Capability =
  | "fs"
  | "net"
  | "child_process"
  | "env"
  | "dynamic_code"
  | "native_addon"
  | "worker"
  | "dynamic_require"
  | "crypto"
  | "os_info";

/** Every capability, in a fixed order. */
export const CAPABILITIES: readonly Capability[] = [
  "fs",
  "net",
  "child_process",
  "env",
  "dynamic_code",
  "native_addon",
  "worker",
  "dynamic_require",
  "crypto",
  "os_info",
];

/** Risk signal IDs. Stable public API; each one is catalogued in `docs/findings.md`. */
export type SignalId =
  | "install-script"
  | "install-script-network"
  | "env-sensitive-read"
  | "env-exfil-pattern"
  | "fs-sensitive-path"
  | "obfuscation"
  | "encoded-payload"
  | "high-entropy-string"
  | "hardcoded-endpoint"
  | "raw-ip-endpoint"
  | "native-binary"
  | "unparseable-file"
  | "oversized-file"
  | "minified-only";

/** One place where a capability is used. */
export interface CapabilityUse {
  /** Package-relative path. */
  file: string;
  /** 1-based line, when the use comes from code (absent for whole-file uses such as `.node` files). */
  line?: number;
  /** Short description such as `require("fs")` or `process.env.HOME`. */
  evidence: string;
}

/** A suspicious pattern. The policy layer may remap `severity`. */
export interface Signal {
  id: SignalId;
  severity: Severity;
  message: string;
  /** Untrusted package content, already stripped of control characters and truncated. */
  evidence: Evidence[];
}

/**
 * How a file was classified.
 * - `js`: `.js`, `.cjs`, `.mjs`, or an extensionless file with a `node` shebang. Parsed.
 * - `json`: `.json`.
 * - `source`: TypeScript or JSX source (`.ts`, `.mts`, `.cts`, `.tsx`, `.jsx`). Not parsed.
 * - `native`: `.node` files and ELF, Mach-O, or PE executables (by magic bytes).
 * - `wasm`: WebAssembly modules (by magic bytes or `.wasm`).
 * - `other`: everything else, including `.d.ts` declaration files.
 */
export type FileKind = "js" | "json" | "source" | "native" | "wasm" | "other";

/** One file in the package. */
export interface FileSummary {
  path: string;
  size: number;
  kind: FileKind;
  /** Hex sha256 of the file contents. */
  sha256: string;
  /** JS files only: looks minified (very long lines, or a `.min.js` name). */
  minified?: boolean;
  /** JS files only: looks like bundler output (webpack, esbuild, browserify, parcel). */
  bundled?: boolean;
}

/** The lifecycle scripts that matter for installs. */
export interface InstallScripts {
  preinstall?: string;
  install?: string;
  postinstall?: string;
  /** Recorded, but npm does not run it when installing from the registry. */
  prepare?: string;
}

/** The static profile of one package. */
export interface PackageProfile {
  name: string;
  version: string;
  scripts: InstallScripts;
  /** Uses per capability, sorted by file, then line. Empty arrays mean "not seen". */
  capabilities: Record<Capability, CapabilityUse[]>;
  /** Sorted by severity, then id, then first evidence file. */
  signals: Signal[];
  /** Sorted by path. */
  files: FileSummary[];
  /** Normalized URL (`scheme://host/path`, no query), host, or IP literals. Sorted, unique. */
  endpoints: string[];
  /** `process.env` keys read with a literal name. Sorted, unique. */
  envKeys: string[];
  stats: {
    /** Files of kind `js`. */
    jsFiles: number;
    parsed: number;
    /** JS files that failed to parse or were too big to analyze. */
    unparsed: number;
    /** Files of kind `source` that were skipped (TypeScript, JSX). */
    skipped: number;
    /** Total unpacked bytes. */
    bytes: number;
  };
}

/** Options for {@link analyzePackage}. */
export interface AnalyzeOptions {
  /** Largest file that is analyzed. Bigger JS files get `oversized-file`. Default 5 MB. */
  maxFileBytes?: number;
  /** More files than this throws `LIMIT_EXCEEDED`. Default 20,000. */
  maxFiles?: number;
  /** Most uses recorded per capability (the rest are dropped). Default 100. */
  maxUsesPerCapability?: number;
  /** Most evidence entries per signal. Default 10. */
  maxEvidence?: number;
}
