// Module hooks: redirect capability builtins imported from node_modules to per-package
// wrapper modules (ADR 0007).
// https://nodejs.org/api/module.html#moduleregisterhooksoptions (Stability 1.2, >= 22.15)

/** Builtin module → capability (mirrors the analyzer's MODULE_CAPS). */
export const BUILTIN_CAPS: Readonly<Record<string, string>> = {
  fs: "fs",
  "fs/promises": "fs",
  http: "net",
  https: "net",
  http2: "net",
  net: "net",
  tls: "net",
  dgram: "net",
  dns: "net",
  "dns/promises": "net",
  child_process: "child_process",
  vm: "dynamic_code",
  worker_threads: "worker",
  cluster: "worker",
  crypto: "crypto",
  os: "os_info",
};

/** URL scheme of the generated wrapper modules. */
export const CAPS_SCHEME = "depward-cap:";

/** `Symbol.for` key of the global the generated modules use to reach the runtime. */
export const REGISTRY_KEY = "depward.caps";

/** `fs` for `fs` and `node:fs`; `null` when the specifier isn't a capability builtin. */
export function capabilityBuiltin(specifier: string): string | null {
  const bare = specifier.startsWith("node:") ? specifier.slice(5) : specifier;
  return Object.hasOwn(BUILTIN_CAPS, bare) ? bare : null;
}

/** The wrapper module URL for builtin `name` imported by package `key`. */
export function capsUrl(name: string, key: string, kind: "cjs" | "esm"): string {
  return `${CAPS_SCHEME}${name}?pkg=${encodeURIComponent(key)}&kind=${kind}`;
}

/** Parses a {@link capsUrl}. `null` for anything else. */
export function parseCapsUrl(url: string): { name: string; key: string; kind: "cjs" | "esm" } | null {
  if (!url.startsWith(CAPS_SCHEME)) return null;
  const u = new URL(url);
  const key = u.searchParams.get("pkg");
  const kind = u.searchParams.get("kind");
  if (key === null || (kind !== "cjs" && kind !== "esm") || !Object.hasOwn(BUILTIN_CAPS, u.pathname)) return null;
  return { name: u.pathname, key, kind };
}

const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/**
 * Source of a wrapper module. CJS: `module.exports` is the package's wrapper. ESM: the
 * wrapper is the default export, and every key of the real module is a named export.
 * Named exports are `let` bindings that the runtime refreshes when
 * `module.syncBuiltinESMExports()` runs, so they stay live like Node's own.
 */
export function generatedSource(name: string, key: string, kind: "cjs" | "esm", exportNames: readonly string[]): { format: "commonjs" | "module"; source: string } {
  const runtime = `globalThis[Symbol.for("depward.caps")]`;
  const call = `${runtime}.moduleFor(${JSON.stringify(name)}, ${JSON.stringify(key)})`;
  if (kind === "cjs") return { format: "commonjs", source: `module.exports = ${call};\n` };
  const names = exportNames.filter((n) => n !== "default" && n !== "__proto__");
  const lines = [`const r = ${runtime};`, `const m = ${call};`, "export default m;"];
  const refresh: string[] = [];
  names.forEach((n, i) => {
    const prop = IDENTIFIER.test(n) ? `m.${n}` : `m[${JSON.stringify(n)}]`;
    lines.push(`let e${i} = ${prop};`, `export { e${i} as ${JSON.stringify(n)} };`);
    refresh.push(`e${i} = ${prop};`);
  });
  if (refresh.length > 0) lines.push(`r.onSync(() => { ${refresh.join(" ")} });`);
  return { format: "module", source: `${lines.join("\n")}\n` };
}

/** What the hooks need from the runtime. */
export interface HookContext {
  /** `name@version` of the package containing a parent URL, or `null` (app code, caps itself). */
  importer(parentURL: string): string | null;
  /** Export names of a real builtin. */
  exportNames(name: string): readonly string[];
}

type ResolveHook = (specifier: string, context: { parentURL?: string; conditions: string[] }, next: (s: string, c?: unknown) => unknown) => unknown;
type LoadHook = (url: string, context: unknown, next: (u: string, c?: unknown) => unknown) => unknown;

/** The resolve and load hooks for `module.registerHooks`. */
export function createHooks(ctx: HookContext): { resolve: ResolveHook; load: LoadHook } {
  return {
    resolve(specifier, context, nextResolve) {
      const name = capabilityBuiltin(specifier);
      if (name !== null && context.parentURL !== undefined) {
        const key = ctx.importer(context.parentURL);
        if (key !== null) {
          const kind = context.conditions.includes("require") ? "cjs" : "esm";
          return { url: capsUrl(name, key, kind), shortCircuit: true };
        }
      }
      return nextResolve(specifier, context);
    },
    load(url, context, nextLoad) {
      const parsed = parseCapsUrl(url);
      if (parsed === null) return nextLoad(url, context);
      const { format, source } = generatedSource(parsed.name, parsed.key, parsed.kind, ctx.exportNames(parsed.name));
      return { format, source, shortCircuit: true };
    },
  };
}
