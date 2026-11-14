// Module hooks: redirect capability builtins imported from node_modules to per-package
// wrapper modules (ADR 0007).
// https://nodejs.org/api/module.html#moduleregisterhooksoptions (Stability 1.2, >= 22.15)
//
// The hooks run when package code imports a builtin, after that code may have replaced
// built-ins, so everything here uses captured intrinsics and plain loops (no URL class,
// no array methods, no for…of).

import {
  DecodeURIComponent,
  EncodeURIComponent,
  JSONStringify,
  ObjectHasOwn,
  RegExpExec,
  StringIndexOf,
  StringSlice,
  StringStartsWith,
} from "./intrinsics.ts";

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
  if (typeof specifier !== "string") return null;
  const bare = StringStartsWith(specifier, "node:") ? StringSlice(specifier, 5) : specifier;
  return ObjectHasOwn(BUILTIN_CAPS, bare) ? bare : null;
}

/** The wrapper module URL for builtin `name` imported by package `key`. */
export function capsUrl(name: string, key: string, kind: "cjs" | "esm"): string {
  return `${CAPS_SCHEME}${name}?pkg=${EncodeURIComponent(key)}&kind=${kind}`;
}

/** Parses a {@link capsUrl} (exactly that shape, read by hand). `null` for anything else. */
export function parseCapsUrl(url: string): { name: string; key: string; kind: "cjs" | "esm" } | null {
  if (typeof url !== "string" || !StringStartsWith(url, CAPS_SCHEME)) return null;
  const q = StringIndexOf(url, "?pkg=");
  const amp = StringIndexOf(url, "&kind=");
  if (q === -1 || amp < q) return null;
  const name = StringSlice(url, CAPS_SCHEME.length, q);
  const kind = StringSlice(url, amp + 6);
  let key: string;
  try {
    key = DecodeURIComponent(StringSlice(url, q + 5, amp));
  } catch {
    return null;
  }
  if ((kind !== "cjs" && kind !== "esm") || !ObjectHasOwn(BUILTIN_CAPS, name)) return null;
  return { name, key, kind };
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
  const call = `${runtime}.moduleFor(${JSONStringify(name)}, ${JSONStringify(key)})`;
  if (kind === "cjs") return { format: "commonjs", source: `module.exports = ${call};\n` };
  let source = `const r = ${runtime};\nconst m = ${call};\nexport default m;\n`;
  let refresh = "";
  let i = 0; // numbers the exported names only
  for (let j = 0; j < exportNames.length; j++) {
    const n = exportNames[j] as string;
    if (n === "default" || n === "__proto__") continue;
    const prop = RegExpExec(IDENTIFIER, n) !== null ? `m.${n}` : `m[${JSONStringify(n)}]`;
    source += `let e${i} = ${prop};\nexport { e${i} as ${JSONStringify(n)} };\n`;
    refresh += ` e${i} = ${prop};`;
    i++;
  }
  if (refresh !== "") source += `r.onSync(() => {${refresh} });\n`;
  return { format: "module", source };
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
          let kind: "cjs" | "esm" = "esm";
          for (let i = 0; i < context.conditions.length; i++) if (context.conditions[i] === "require") kind = "cjs";
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
