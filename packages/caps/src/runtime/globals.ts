// Global capabilities that no import reveals, attributed through the stack
// (docs/specs/caps.md § Runtime details, ADR 0007 question 4).

import type { Attribution } from "./attribution.ts";
import { capabilityBuiltin } from "./hooks.ts";
import { ProxyCtor, ReflectApply, ReflectConstruct, ReflectGet, ReflectGetOwnPropertyDescriptor, ReflectOwnKeys, RegExpExec } from "./intrinsics.ts";
import type { Store, UseRecord } from "./store.ts";

const SECRET_WORD = /TOKEN|SECRET|KEY|PASSWORD/i;
const VENDOR_PREFIX = /^(?:NPM_|AWS_|GITHUB_|GH_|CI_JOB)/;

/** Credential-like env keys: the analyzer's `env-sensitive-read` rule. Uses the captured RegExp exec. */
export function isSensitiveEnvKey(key: string): boolean {
  return RegExpExec(SECRET_WORD, key) !== null || RegExpExec(VENDOR_PREFIX, key) !== null;
}

/** What {@link installGlobals} needs. */
export interface GlobalsContext {
  attribution: Attribution;
  store: Store;
  use: (record: UseRecord) => void;
  /** The package's wrapper of a capability builtin. */
  moduleFor: (name: string, key: string) => object;
  /** Attribute every env read, not only credential-like keys. */
  envAll: boolean;
}

function wrapClass(name: string, ctx: GlobalsContext): void {
  const desc = Object.getOwnPropertyDescriptor(globalThis, name);
  if (desc === undefined) return;
  let wrapped: unknown;
  const wrap = (real: unknown): unknown => {
    if (typeof real !== "function") return real;
    if (wrapped === undefined) {
      wrapped = new ProxyCtor(real, {
        construct(target, args: unknown[], newTarget: (...a: unknown[]) => unknown) {
          const key = ctx.attribution.caller();
          if (key !== null) ctx.use(ctx.store.record(key, "net", `globalThis.${name}`));
          return ReflectConstruct(target, args, newTarget === wrapped ? target : newTarget);
        },
      });
    }
    return wrapped;
  };
  if ("value" in desc) {
    Object.defineProperty(globalThis, name, { ...desc, value: wrap(desc.value) });
  } else if (desc.get !== undefined) {
    // Node defines some globals as lazy getters: keep them lazy.
    const get = desc.get;
    Object.defineProperty(globalThis, name, { ...desc, get: () => wrap(ReflectApply(get, globalThis, [])) });
  }
}

/** Replaces the global capability entry points with attributing wrappers. */
export function installGlobals(ctx: GlobalsContext): void {
  const { attribution, store, use } = ctx;
  const count = (key: string | null, cap: string, member: string): void => {
    if (key !== null) use(store.record(key, cap, member));
  };

  const realFetch = globalThis.fetch;
  if (typeof realFetch === "function") {
    globalThis.fetch = function fetch(this: unknown, input: Parameters<typeof globalThis.fetch>[0], init?: RequestInit) {
      count(attribution.caller(), "net", "globalThis.fetch");
      return ReflectApply(realFetch, this, [input, init]) as Promise<Response>;
    };
  }
  wrapClass("WebSocket", ctx);
  wrapClass("EventSource", ctx);

  const realGetBuiltin = process.getBuiltinModule;
  if (typeof realGetBuiltin === "function") {
    process.getBuiltinModule = function getBuiltinModule(id: string) {
      const real = ReflectApply(realGetBuiltin, process, [id]) as object | undefined;
      const name = typeof id === "string" ? capabilityBuiltin(id) : null;
      if (name === null || real === undefined) return real;
      const key = attribution.caller();
      return key === null ? real : ctx.moduleFor(name, key);
    } as typeof process.getBuiltinModule;
  }

  const realDlopen = process.dlopen;
  process.dlopen = function dlopen(this: unknown, ...args: unknown[]) {
    count(attribution.caller(true), "native_addon", "process.dlopen");
    return ReflectApply(realDlopen, this, args) as void;
  } as typeof process.dlopen;

  const realEnv = process.env;
  process.env = new ProxyCtor(realEnv, {
    get(target, name) {
      if (typeof name === "string" && (ctx.envAll || isSensitiveEnvKey(name))) count(attribution.caller(), "env", `process.env.${name}`);
      return ReflectGet(target, name);
    },
    ownKeys(target) {
      count(attribution.caller(), "env", "process.env (enumerate)");
      return ReflectOwnKeys(target);
    },
    getOwnPropertyDescriptor(target, name) {
      return ReflectGetOwnPropertyDescriptor(target, name);
    },
  });
}
