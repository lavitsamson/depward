import { createHash } from "node:crypto";
import { posix } from "node:path";
import { DepwardError, type Evidence, type PackageFile, type PackageFiles } from "@depward/core";
import { classifyFile, looksBundled, looksMinified } from "./classify.ts";
import { parseJs } from "./parse.ts";
import { INSTALL_HOOKS, readInstallScripts, resolveLocal, scriptEntryWords, scriptNetworkReason } from "./scripts.ts";
import { compareSignals, makeSignal } from "./signals.ts";
import { clean, findEndpoints } from "./text.ts";
import {
  CAPABILITIES,
  type AnalyzeOptions,
  type Capability,
  type CapabilityUse,
  type FileSummary,
  type PackageProfile,
  type Signal,
  type SignalId,
} from "./types.ts";
import { analyzeProgram, type FileFacts, type Hit } from "./visit.ts";

// package.json fields that hold documentation links rather than endpoints the code uses.
const PKG_DOC_FIELDS = new Set(["repository", "homepage", "bugs", "author", "contributors", "maintainers", "funding", "license"]);

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Statically profiles one package: its capabilities, risk signals, files, endpoints, and
 * env keys. It never executes package code. Pass the output of `readTarball`.
 *
 * Throws a `DepwardError` with `LIMIT_EXCEEDED` (too many files) or `INVALID_ARCHIVE`
 * (no readable `package.json` object at the package root).
 */
export function analyzePackage(pkgFiles: PackageFiles, opts: AnalyzeOptions = {}): PackageProfile {
  const maxFileBytes = opts.maxFileBytes ?? 5 * 1024 * 1024;
  const maxFiles = opts.maxFiles ?? 20_000;
  const maxUses = opts.maxUsesPerCapability ?? 100;
  const maxEvidence = opts.maxEvidence ?? 10;
  if (pkgFiles.files.length > maxFiles) throw new DepwardError("LIMIT_EXCEEDED", `package has more than ${maxFiles} files`);

  const byPath = new Map(pkgFiles.files.map((f) => [f.path, f]));
  const pkg = readPackageJson(byPath.get("package.json"));
  const signals: Signal[] = [];
  const add = (id: SignalId, message: string, evidence: Evidence[]): void => {
    if (evidence.length > 0) signals.push(makeSignal(id, message, evidence, maxEvidence));
  };
  const uses: Record<Capability, CapabilityUse[]> = Object.fromEntries(CAPABILITIES.map((c) => [c, []])) as never;
  const facts = new Map<string, FileFacts>();
  const files: FileSummary[] = [];
  const endpoints = new Set<string>();
  const envKeys = new Set<string>();
  const stats = { jsFiles: 0, parsed: 0, unparsed: 0, skipped: 0, bytes: pkgFiles.unpackedSize };
  const minified: boolean[] = [];

  for (const file of pkgFiles.files) {
    const c = classifyFile(file.path, file.data);
    const summary: FileSummary = { path: file.path, size: file.data.byteLength, kind: c.kind, sha256: sha256(file.data) };
    files.push(summary);
    if (c.kind === "source") stats.skipped++;
    if (c.kind === "native" || c.kind === "wasm") {
      add("native-binary", `ships a native binary (${c.format ?? c.kind})`, [{ file: file.path, detail: c.format ?? c.kind }]);
      if (/\.node$/i.test(file.path)) uses.native_addon.push({ file: file.path, evidence: ".node file" });
    }
    if (c.kind !== "js") continue;

    stats.jsFiles++;
    if (file.data.byteLength > maxFileBytes) {
      stats.unparsed++;
      add("oversized-file", "file is too large to analyze", [{ file: file.path, detail: `${file.data.byteLength} bytes (limit ${maxFileBytes})` }]);
      continue;
    }
    const text = new TextDecoder().decode(file.data);
    summary.minified = looksMinified(file.path, text);
    summary.bundled = looksBundled(text);
    if (file.data.byteLength >= 512) minified.push(summary.minified);
    const result = analyzeText(text);
    if ("error" in result) {
      stats.unparsed++;
      add("unparseable-file", "JavaScript file could not be parsed", [{ file: file.path, detail: clean(result.error) }]);
      continue;
    }
    stats.parsed++;
    const f = result.facts;
    facts.set(file.path, f);
    fileSignals(file.path, f, add);
    for (const u of f.uses) uses[u.cap].push({ file: file.path, line: u.line, evidence: u.evidence });
    for (const k of f.envKeys) envKeys.add(k);
    for (const e of f.endpoints) endpoints.add(e.endpoint);
  }

  // Endpoints in package.json (scripts, config), excluding documentation fields.
  const pkgEndpoints: Evidence[] = [];
  for (const [key, value] of Object.entries(pkg)) {
    if (PKG_DOC_FIELDS.has(key)) continue;
    forEachString(value, (s) => {
      for (const e of findEndpoints(s)) {
        endpoints.add(e.endpoint);
        pkgEndpoints.push({ file: "package.json", snippet: clean(e.endpoint), detail: key });
      }
    });
  }
  add("hardcoded-endpoint", "contains hardcoded network endpoints", pkgEndpoints);

  const scripts = readInstallScripts(pkg, byPath.has("binding.gyp"));
  installSignals(scripts, byPath, facts, add);

  if (minified.length > 0 && minified.every(Boolean)) {
    add("minified-only", "ships only minified code", [{ detail: `${minified.length} JS file(s), all minified` }]);
  }

  return {
    name: typeof pkg["name"] === "string" ? pkg["name"] : "",
    version: typeof pkg["version"] === "string" ? pkg["version"] : "",
    scripts,
    capabilities: Object.fromEntries(CAPABILITIES.map((c) => [c, dedupeUses(uses[c], maxUses)])) as Record<Capability, CapabilityUse[]>,
    signals: signals.toSorted(compareSignals),
    files,
    endpoints: [...endpoints].toSorted(cmp),
    envKeys: [...envKeys].toSorted(cmp),
    stats,
  };
}

function fileSignals(file: string, f: FileFacts, add: (id: SignalId, message: string, evidence: Evidence[]) => void): void {
  const ev = (hits: Hit[]): Evidence[] => hits.map((h) => withoutUndefined({ file, line: h.line, snippet: h.snippet, detail: h.detail }));
  add("env-sensitive-read", "reads sensitive environment variables", ev(f.envSensitive));
  add("env-exfil-pattern", "sends sensitive environment variables over the network", ev(f.envExfil));
  add("fs-sensitive-path", "references credential, browser-profile, or wallet locations", ev(f.sensitivePaths));
  add("obfuscation", "code looks obfuscated", f.obfuscation.map((detail) => ({ file, detail })));
  add("encoded-payload", "decodes a large encoded literal and executes or writes it", ev(f.encodedPayloads));
  add("high-entropy-string", "contains long high-entropy string literals", ev(f.highEntropy));
  add("hardcoded-endpoint", "contains hardcoded network endpoints", f.endpoints.map((e) => ({ file, line: e.line, snippet: clean(e.endpoint) })));
  add("raw-ip-endpoint", "makes network calls to a raw IP address", ev(f.rawIp));
}

function installSignals(
  scripts: ReturnType<typeof readInstallScripts>,
  byPath: Map<string, PackageFile>,
  facts: Map<string, FileFacts>,
  add: (id: SignalId, message: string, evidence: Evidence[]) => void,
): void {
  const hooks = INSTALL_HOOKS.filter((h) => scripts[h] !== undefined);
  add("install-script", `runs install scripts (${hooks.join(", ")})`, hooks.map((h) => ({ file: "package.json", snippet: clean(scripts[h] ?? ""), detail: h })));
  const network: Evidence[] = [];
  for (const h of hooks) {
    const script = scripts[h] ?? "";
    const why = scriptNetworkReason(script) ?? netReachableFrom(script, byPath, facts);
    if (why) network.push({ file: "package.json", snippet: clean(script), detail: `${h}: ${why}` });
  }
  add("install-script-network", "an install script can reach the network", network);
}

/** Follows the JS files a script runs (and their relative imports) looking for `net`. */
function netReachableFrom(script: string, byPath: Map<string, PackageFile>, facts: Map<string, FileFacts>): string | undefined {
  const has = (p: string): boolean => byPath.has(p);
  const queue = scriptEntryWords(script).flatMap((w) => resolveLocal(".", w, has) ?? []);
  const seen = new Set<string>(queue);
  while (queue.length > 0 && seen.size <= 500) {
    const path = queue.shift() ?? "";
    const f = facts.get(path);
    if (!f) continue;
    if (f.uses.some((u) => u.cap === "net")) return `runs ${clean(path, 80)}, which uses the network`;
    for (const spec of f.localImports) {
      const next = resolveLocal(posix.dirname(path), spec, has);
      if (next !== undefined && !seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return undefined;
}

function readPackageJson(file: PackageFile | undefined): Record<string, unknown> {
  if (!file) throw new DepwardError("INVALID_ARCHIVE", "package has no package.json");
  let pkg: unknown;
  try {
    pkg = JSON.parse(new TextDecoder().decode(file.data));
  } catch (err) {
    throw new DepwardError("INVALID_ARCHIVE", "package.json is not valid JSON", { cause: err });
  }
  if (pkg === null || typeof pkg !== "object" || Array.isArray(pkg)) throw new DepwardError("INVALID_ARCHIVE", "package.json is not an object");
  return pkg as Record<string, unknown>;
}

function forEachString(value: unknown, cb: (s: string) => void, depth = 0): void {
  if (depth > 20) return;
  if (typeof value === "string") cb(value);
  else if (Array.isArray(value)) for (const v of value) forEachString(v, cb, depth + 1);
  else if (value !== null && typeof value === "object") for (const v of Object.values(value)) forEachString(v, cb, depth + 1);
}

function dedupeUses(list: CapabilityUse[], max: number): CapabilityUse[] {
  const seen = new Set<string>();
  const out: CapabilityUse[] = [];
  const sorted = list.toSorted((a, b) => cmp(a.file, b.file) || (a.line ?? 0) - (b.line ?? 0) || cmp(a.evidence, b.evidence));
  for (const u of sorted) {
    const key = `${u.file}\0${u.evidence}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(u);
  }
  return out.slice(0, max);
}

function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function withoutUndefined(e: { file: string; line: number; snippet: string | undefined; detail: string | undefined }): Evidence {
  const out: Evidence = { file: e.file, line: e.line };
  if (e.snippet !== undefined) out.snippet = e.snippet;
  if (e.detail !== undefined) out.detail = e.detail;
  return out;
}

/**
 * Parses and visits one file. A pathologically nested file can exhaust the stack in the
 * parser or the walker; that is reported as an unparseable file rather than thrown.
 */
function analyzeText(text: string): { facts: FileFacts } | { error: string } {
  try {
    const parsed = parseJs(text);
    return "error" in parsed ? parsed : { facts: analyzeProgram(parsed.program) };
  } catch (err) {
    if (err instanceof RangeError) return { error: "too deeply nested to analyze" };
    throw err;
  }
}
