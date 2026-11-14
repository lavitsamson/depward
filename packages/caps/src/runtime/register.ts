// `node --import @depward/caps/register app.js`: attribute capability use to packages
// (observe), or refuse uses that capabilities.lock.json doesn't approve (enforce).
// Spec: docs/specs/caps.md § Runtime details, § Enforce details; design: ADR 0007.
//
// This is defense in depth, NOT a sandbox: code in the same process can bypass it (for
// example through process.binding, Module._load, native addons, or real module objects
// the application hands over). See the package README.
//
// Only node: builtins are imported here, statically, so they load before the hooks
// exist and are the real modules.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import * as nodeModule from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isMainThread } from "node:worker_threads";
import { createAttribution } from "./attribution.ts";
import { installGlobals } from "./globals.ts";
import { BUILTIN_CAPS, REGISTRY_KEY, createHooks } from "./hooks.ts";
import { ReflectApply } from "./intrinsics.ts";
import { DepwardCapabilityError } from "./errors.ts";
import { DEFAULT_OBSERVED_PATH } from "./paths.ts";
import { parsePolicy, type RuntimePolicy } from "./policy.ts";
import { createStore, writeObserved, type UseRecord } from "./store.ts";
import { createWrapper } from "./wrap.ts";

/** Default capability lockfile for enforce mode, relative to the working directory. */
const DEFAULT_POLICY_PATH = "capabilities.lock.json";

/**
 * Enforce mode's policy. Fails closed: a missing or invalid capability lockfile throws
 * at startup, so the application never runs unprotected by accident.
 */
function loadPolicy(path: string): RuntimePolicy {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new DepwardCapabilityError("CAPS_POLICY", `enforce mode needs a capability lockfile, and ${path} can't be read (create it with "depward caps scan", or set DEPWARD_CAPS_LOCKFILE)`);
  }
  return parsePolicy(text, path);
}

/** Observe mode: count the use. */
function countUse(record: UseRecord): void {
  record.count++;
}

function install(): void {
  const registerHooks = (nodeModule as { registerHooks?: (hooks: object) => unknown }).registerHooks;
  if (typeof registerHooks !== "function") {
    process.emitWarning("@depward/caps/register needs Node.js >= 22.15 (module.registerHooks); capability use is not observed", { code: "DEPWARD_CAPS_UNSUPPORTED" });
    return;
  }
  const env = process.env;
  const mode = env["DEPWARD_CAPS_MODE"] ?? "";
  const enforce = mode === "enforce";
  if (!enforce && mode !== "" && mode !== "observe") {
    process.emitWarning(`unknown DEPWARD_CAPS_MODE=${mode} (use observe or enforce); observing`, { code: "DEPWARD_CAPS_MODE" });
  }
  const policy = enforce ? loadPolicy(resolve(process.cwd(), env["DEPWARD_CAPS_LOCKFILE"] || DEFAULT_POLICY_PATH)) : null;
  const outPath = resolve(process.cwd(), env["DEPWARD_CAPS_OUT"] || DEFAULT_OBSERVED_PATH);
  const envAll = env["DEPWARD_CAPS_ENV"] === "all";

  // Our own code: the directory of this file (src/runtime/ from source, dist/ when
  // installed). Not the package root, which would also cover test fixture apps.
  const root = dirname(fileURLToPath(import.meta.url));
  const attribution = createAttribution({
    selfRoots: [`${pathToFileURL(root).href}/`, `${root.replaceAll("\\", "/")}/`],
    readFile: (path) => readFileSync(path, "utf8"),
  });
  const store = createStore(policy === null ? undefined : (key, cap) => policy.allows(key, cap));
  // Enforce: the decision was made when the record was created; denial costs a stack
  // capture for the call site, approval costs nothing extra.
  const use =
    policy === null
      ? countUse
      : (record: UseRecord): void => {
          record.count++;
          if (!record.allowed) throw DepwardCapabilityError.denied({ package: record.key, capability: record.cap, member: record.member, callSite: attribution.site() });
        };
  const wrapper = createWrapper({ store, use });

  const getBuiltin = process.getBuiltinModule;
  const real = (name: string): object => ReflectApply(getBuiltin, process, [`node:${name}`]) as object;
  const moduleFor = (name: string, key: string): object => wrapper.wrapModule(real(name), name, BUILTIN_CAPS[name] ?? name, key);

  // Live ESM bindings: generated modules register a refresher; it runs whenever the
  // application calls module.syncBuiltinESMExports().
  const syncers: (() => void)[] = [];
  const onSync = (fn: () => void): void => {
    syncers.push(fn);
  };
  const cjsModule = real("module") as { syncBuiltinESMExports: () => void };
  const realSync = cjsModule.syncBuiltinESMExports;
  cjsModule.syncBuiltinESMExports = function syncBuiltinESMExports(): void {
    ReflectApply(realSync, cjsModule, []);
    for (const fn of syncers) fn();
  };
  ReflectApply(realSync, cjsModule, []); // so `import { syncBuiltinESMExports }` sees the wrapper

  Object.defineProperty(globalThis, Symbol.for(REGISTRY_KEY), { value: Object.freeze({ moduleFor, onSync }) });

  registerHooks(
    createHooks({
      importer: (parentURL) => (attribution.isSelf(parentURL) ? null : attribution.keyOf(parentURL)),
      exportNames: (name) => Object.keys(real(name)),
    }),
  );
  installGlobals({ attribution, store, use, moduleFor, envAll });

  process.on("exit", () => {
    try {
      writeObserved(outPath, dirname(outPath), store.snapshot(), {
        readFile: (p) => readFileSync(p, "utf8"),
        writeFile: (p, text) => writeFileSync(p, text),
        rename: (from, to) => renameSync(from, to),
        mkdir: (d) => mkdirSync(d, { recursive: true }),
      });
    } catch (err) {
      process.emitWarning(`@depward/caps could not write ${outPath}: ${(err as Error).message}`, { code: "DEPWARD_CAPS_WRITE" });
    }
  });
}

// Worker threads are not observed in M4.3 (docs/specs/caps.md § Runtime details).
if (isMainThread) install();
