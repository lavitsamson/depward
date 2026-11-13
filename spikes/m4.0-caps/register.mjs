// M4.0 spike: per-package wrapped builtins through module.registerHooks().
// Throwaway code that answers the questions in docs/specs/caps.md; the real implementation
// lands in @depward/caps (M4.3/M4.4). Findings: docs/adr/0007-caps-runtime-hooks.md.
//
// Docs (checked 2026-11-13):
//   https://nodejs.org/api/module.html#moduleregisterhooksoptions  (Stability 1.2, >= 22.15)
//   https://nodejs.org/api/util.html#utilgetcallsitesframecount-options
//
// Usage: node --import ./register.mjs app.mjs
//   DEPWARD_CAPS_MODE=observe|enforce   (default observe)
//   DEPWARD_CAPS_POLICY=<file.json>     { "<pkg>": ["fs", "net"] }   (enforce mode)
//   DEPWARD_CAPS_OUT=<file.json>        observations written on exit
//   DEPWARD_CAPS_GLOBALS=0              skip the fetch / process.env wrappers
//   DEPWARD_CAPS_STACK=error|callsites  stack capture strategy for globals (default error)
import { registerHooks, createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { getCallSites } from "node:util";

const require = createRequire(import.meta.url);
const SCHEME = "depward-cap:";
// The real package will skip its own install directory; the spike skips only this file.
const SELF_URL = import.meta.url;

/** Builtin module → capability. Mirrors packages/analyzer/src/tables.ts MODULE_CAPS. */
const CAPS = {
  fs: "fs", "fs/promises": "fs",
  http: "net", https: "net", http2: "net", net: "net", tls: "net", dgram: "net", dns: "net", "dns/promises": "net",
  child_process: "child_process", vm: "dynamic_code", worker_threads: "worker", cluster: "worker",
  crypto: "crypto", os: "os_info",
};

const MODE = process.env.DEPWARD_CAPS_MODE === "enforce" ? "enforce" : "observe";
const POLICY = process.env.DEPWARD_CAPS_POLICY ? JSON.parse(readFileSync(process.env.DEPWARD_CAPS_POLICY, "utf8")) : {};
const STACK = process.env.DEPWARD_CAPS_STACK === "callsites" ? "callsites" : "error";

export class DepwardCapabilityError extends Error {
  constructor(pkg, cap, member) {
    super(`depward: package "${pkg}" used capability "${cap}" (${member}) without approval`);
    this.name = "DepwardCapabilityError";
    this.code = "CAPS_DENIED";
    this.package = pkg;
    this.capability = cap;
  }
}

// ---------------------------------------------------------------------------------------
// Attribution: file URL or path → package name (last node_modules segment).

/** @returns {string | null} package name, or null for application code / unknown. */
export function packageOf(location) {
  if (typeof location !== "string") return null;
  const s = location.replaceAll("\\", "/");
  const i = s.lastIndexOf("/node_modules/");
  if (i === -1) return null;
  const parts = s.slice(i + 14).split("/");
  const name = parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
  try { return decodeURIComponent(name); } catch { return name; }
}

// ---------------------------------------------------------------------------------------
// Observation store. One record per (package, capability, member); counters are bumped
// in the hot path, so each wrapper holds its own record and nothing is looked up per call.

const records = new Map();
function record(pkg, cap, member) {
  const key = `${pkg}\0${cap}\0${member}`;
  let r = records.get(key);
  if (r === undefined) {
    const allowed = MODE === "observe" || (POLICY[pkg] ?? []).includes(cap);
    r = { pkg, cap, member, count: 0, allowed };
    records.set(key, r);
  }
  return r;
}
function use(r) {
  r.count++;
  if (!r.allowed) throw new DepwardCapabilityError(r.pkg, r.cap, r.member);
}

// ---------------------------------------------------------------------------------------
// Wrappers. Proxies keep `instanceof`, `new`, subclassing and statics working because
// every non-trapped operation (including `.prototype`) forwards to the real target.

const fnProxies = new WeakMap(); // real fn → Map<pkg, proxy>
const objProxies = new WeakMap(); // real object → Map<pkg, proxy>
const proxyTargets = new WeakMap(); // object proxy → real object (to unwrap `this`)

function wrapFn(fn, cap, pkg, member) {
  let byPkg = fnProxies.get(fn);
  if (byPkg === undefined) fnProxies.set(fn, (byPkg = new Map()));
  let p = byPkg.get(pkg);
  if (p !== undefined) return p;
  const r = record(pkg, cap, member);
  p = new Proxy(fn, {
    apply(target, thisArg, args) {
      use(r);
      return Reflect.apply(target, proxyTargets.get(thisArg) ?? thisArg, args);
    },
    construct(target, args, newTarget) {
      use(r);
      return Reflect.construct(target, args, newTarget === p ? target : newTarget);
    },
  });
  byPkg.set(pkg, p);
  return p;
}

function wrapObject(obj, cap, pkg, path) {
  let byPkg = objProxies.get(obj);
  if (byPkg === undefined) objProxies.set(obj, (byPkg = new Map()));
  let p = byPkg.get(pkg);
  if (p !== undefined) return p;
  // key → [real value, returned value]. Re-validated against the real value on every get,
  // so monkey patches of the real module are picked up.
  const memo = new Map();
  p = new Proxy(obj, {
    get(target, key) {
      const v = Reflect.get(target, key, target);
      if (typeof key === "symbol") return v;
      const m = memo.get(key);
      if (m !== undefined && m[0] === v) return m[1];
      let out = v;
      const d = Reflect.getOwnPropertyDescriptor(target, key);
      if (d !== undefined && !d.configurable && "value" in d && !d.writable) out = v; // proxy invariant
      else if (typeof v === "function") out = wrapFn(v, cap, pkg, `${path}.${key}`);
      else if (key === "promises" && v !== null && typeof v === "object") out = wrapObject(v, cap, pkg, `${path}.promises`);
      memo.set(key, [v, out]);
      return out;
    },
  });
  proxyTargets.set(p, obj);
  byPkg.set(pkg, p);
  return p;
}

/** Called from the generated wrapper modules. */
function moduleFor(name, pkg) {
  return wrapObject(require(`node:${name}`), CAPS[name], pkg, name);
}
Object.defineProperty(globalThis, Symbol.for("depward.caps"), { value: Object.freeze({ moduleFor }) });

// ---------------------------------------------------------------------------------------
// Hooks.

function generatedSource(name, pkg, kind) {
  const call = `globalThis[Symbol.for("depward.caps")].moduleFor(${JSON.stringify(name)}, ${JSON.stringify(pkg)})`;
  if (kind === "cjs") return { format: "commonjs", source: `module.exports = ${call};\n` };
  // ESM: named exports are generated from the real module's keys. They are snapshots
  // taken at link time (see ADR: live bindings).
  const names = Object.keys(require(`node:${name}`)).filter((n) => n !== "default");
  const lines = [`const m = ${call};`, "export default m;"];
  names.forEach((n, i) => lines.push(`const e${i} = m[${JSON.stringify(n)}];`, `export { e${i} as ${JSON.stringify(n)} };`));
  return { format: "module", source: lines.join("\n") };
}

registerHooks({
  resolve(specifier, context, nextResolve) {
    const bare = specifier.startsWith("node:") ? specifier.slice(5) : specifier;
    if (Object.hasOwn(CAPS, bare) && context.parentURL !== undefined && context.parentURL !== SELF_URL) {
      const pkg = packageOf(context.parentURL);
      if (pkg !== null) {
        const kind = context.conditions.includes("require") ? "cjs" : "esm";
        return { url: `${SCHEME}${bare}?pkg=${encodeURIComponent(pkg)}&kind=${kind}`, shortCircuit: true };
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (!url.startsWith(SCHEME)) return nextLoad(url, context);
    const u = new URL(url);
    const { format, source } = generatedSource(u.pathname, u.searchParams.get("pkg"), u.searchParams.get("kind"));
    return { format, source, shortCircuit: true };
  },
});

// ---------------------------------------------------------------------------------------
// Globals: stack-trace attribution (spec question 4).

function callerFromError(skip) {
  const holder = {};
  const limit = Error.stackTraceLimit;
  Error.stackTraceLimit = 12;
  Error.captureStackTrace(holder, skip);
  Error.stackTraceLimit = limit;
  const stack = holder.stack ?? "";
  // The first frame with a location decides. Frames above `skip` are cut by V8; frames
  // without a location (`<anonymous>`, e.g. Reflect.get or Array.map) are skipped. If the
  // first located frame is Node's own code (node:internal/...), Node itself made the
  // access (for example the module loader reading WATCH_REPORT_DEPENDENCIES), so nothing
  // is attributed.
  for (const line of stack.split("\n").slice(1)) {
    if (line.includes("(node:") || line.includes("at node:")) return null;
    if (!/(file:|[/\\])/.test(line)) continue;
    return packageOf(line);
  }
  return null;
}
function callerFromCallSites() {
  // [0] = this function, [1] = callerPackage, [2] = the wrapper, [3] = caller.
  for (const site of getCallSites(8).slice(3)) {
    const file = site.scriptName;
    if (!file) continue;
    if (file.startsWith("node:")) return null;
    return packageOf(file);
  }
  return null;
}
/** Credential-like env keys (same rule as the analyzer's env-sensitive-read). */
const sensitive = (key) => /TOKEN|SECRET|KEY|PASSWORD/i.test(key) || /^(?:NPM_|AWS_|GITHUB_|GH_|CI_JOB)/.test(key);

export function callerPackage(skip) {
  return STACK === "callsites" ? callerFromCallSites() : callerFromError(skip);
}

if (process.env.DEPWARD_CAPS_GLOBALS !== "0") {
  const realFetch = globalThis.fetch;
  if (typeof realFetch === "function") {
    globalThis.fetch = function fetch(input, init) {
      const pkg = callerPackage(fetch);
      if (pkg !== null) use(record(pkg, "net", "globalThis.fetch"));
      return Reflect.apply(realFetch, this, [input, init]);
    };
  }
  const realGetBuiltin = process.getBuiltinModule;
  if (typeof realGetBuiltin === "function") {
    process.getBuiltinModule = function getBuiltinModule(id) {
      const real = Reflect.apply(realGetBuiltin, process, [id]);
      const bare = typeof id === "string" && id.startsWith("node:") ? id.slice(5) : id;
      const pkg = Object.hasOwn(CAPS, bare) ? callerPackage(getBuiltinModule) : null;
      return pkg === null ? real : moduleFor(bare, pkg);
    };
  }
  const realEnv = process.env;
  // Stack capture costs ~25 µs, so by default only credential-like keys are attributed
  // (same rule as the analyzer's env-sensitive-read), plus enumeration of the whole
  // environment (the exfiltration pattern). DEPWARD_CAPS_ENV=all attributes every read.
  const ALL_ENV = process.env.DEPWARD_CAPS_ENV === "all";
  // Named so captureStackTrace can cut the stack at the trap.
  const envGet = function envGet(target, key) {
    if (typeof key === "string" && (ALL_ENV || sensitive(key))) {
      const pkg = callerPackage(envGet);
      if (pkg !== null) use(record(pkg, "env", `process.env.${key}`));
    }
    return Reflect.get(target, key);
  };
  const envKeys = function envKeys(target) {
    const pkg = callerPackage(envKeys);
    if (pkg !== null) use(record(pkg, "env", "process.env (enumerate)"));
    return Reflect.ownKeys(target);
  };
  process.env = new Proxy(realEnv, { get: envGet, ownKeys: envKeys });
}

process.on("exit", () => {
  const out = process.env.DEPWARD_CAPS_OUT;
  if (!out) return;
  const rows = [...records.values()].filter((r) => r.count > 0).map(({ pkg, cap, member, count }) => ({ pkg, cap, member, count }));
  rows.sort((a, b) => a.pkg.localeCompare(b.pkg) || a.cap.localeCompare(b.cap) || a.member.localeCompare(b.member));
  writeFileSync(out, JSON.stringify({ version: 1, mode: MODE, observed: rows }, null, 2) + "\n");
});
