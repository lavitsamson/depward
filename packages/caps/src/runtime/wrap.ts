// Per-package wrappers of builtin modules (ADR 0007). A module becomes a Proxy whose
// `get` wraps functions in function Proxies (`apply` + `construct` traps), so
// `instanceof`, `new`, subclassing and statics keep working: every untrapped operation,
// including `.prototype`, forwards to the real target.

import {
  ProxyCtor,
  ReflectApply,
  ReflectConstruct,
  ReflectDefineProperty,
  ReflectGet,
  ReflectGetOwnPropertyDescriptor,
  ReflectSet,
  SafeMap,
  SafeWeakMap,
} from "./intrinsics.ts";
import type { Store, UseRecord } from "./store.ts";

/** Options for {@link createWrapper}. */
export interface WrapperOptions {
  store: Store;
  /** Called on every use, before the real function runs. Observe mode counts; enforce mode (M4.4) may throw. */
  use: (record: UseRecord) => void;
}

/** Builds and caches per-package wrappers. */
export interface Wrapper {
  /** The wrapper of `real` (a builtin module object) for package `key`, counting under `cap`. */
  wrapModule(real: object, path: string, cap: string, key: string): object;
  /** The real function or object behind a wrapper, or `value` itself. */
  unwrap(value: unknown): unknown;
}

/** The per-package cache entry of `real`, and the wrapper for `key` if there is one. */
function cached(cache: SafeWeakMap<object, SafeMap<string, object>>, real: object, key: string): { byKey: SafeMap<string, object>; hit: object | undefined } {
  let byKey = cache.get(real);
  if (byKey === undefined) {
    byKey = new SafeMap();
    cache.set(real, byKey);
  }
  return { byKey, hit: byKey.get(key) };
}

export function createWrapper(opts: WrapperOptions): Wrapper {
  const fnProxies = new SafeWeakMap<object, SafeMap<string, object>>();
  const objProxies = new SafeWeakMap<object, SafeMap<string, object>>();
  const targets = new SafeWeakMap<object, object>(); // wrapper → real

  const unwrap = (value: unknown): unknown => {
    if ((typeof value !== "object" && typeof value !== "function") || value === null) return value;
    return targets.get(value) ?? value;
  };

  const wrapFn = (fn: (...args: unknown[]) => unknown, cap: string, key: string, member: string): object => {
    const { byKey, hit } = cached(fnProxies, fn, key);
    if (hit !== undefined) return hit;
    const record = opts.store.record(key, cap, member);
    const use = opts.use;
    const proxy: object = new ProxyCtor(fn, {
      // Own function-valued properties (`fs.exists[util.promisify.custom]`,
      // `fs.realpathSync.native`) are wrapped too, or they'd bypass counting. Inherited
      // ones (`call`, `bind`, `Symbol.hasInstance`) are left alone.
      get(target, name) {
        const v: unknown = ReflectGet(target, name, target);
        if (typeof v !== "function") return v;
        const d = ReflectGetOwnPropertyDescriptor(target, name);
        if (d === undefined || !("value" in d) || (d.configurable === false && d.writable === false)) return v;
        const label = typeof name === "symbol" ? `${member}[${name.description ?? "symbol"}]` : `${member}.${name}`;
        return wrapFn(v as (...args: unknown[]) => unknown, cap, key, label);
      },
      apply(target, thisArg: unknown, args: unknown[]) {
        use(record);
        return ReflectApply(target, unwrap(thisArg), args);
      },
      construct(target, args: unknown[], newTarget: (...a: unknown[]) => unknown) {
        use(record);
        return ReflectConstruct(target, args, newTarget === proxy ? target : newTarget);
      },
    });
    targets.set(proxy, fn);
    byKey.set(key, proxy);
    return proxy;
  };

  const wrapModule = (real: object, path: string, cap: string, key: string): object => {
    const { byKey, hit } = cached(objProxies, real, key);
    if (hit !== undefined) return hit;
    // name → [real value, returned value]; re-validated on every get, so later patches of
    // the real module are seen.
    const memo = new SafeMap<string, [unknown, unknown]>();
    const proxy: object = new ProxyCtor(real, {
      get(target, name) {
        const v: unknown = ReflectGet(target, name, target);
        if (typeof name === "symbol") return v;
        const m = memo.get(name);
        if (m !== undefined && m[0] === v) return m[1];
        let out = v;
        const d = ReflectGetOwnPropertyDescriptor(target, name);
        if (d !== undefined && d.configurable === false && "value" in d && d.writable === false) out = v; // proxy invariant
        else if (typeof v === "function") out = wrapFn(v as (...args: unknown[]) => unknown, cap, key, `${path}.${name}`);
        else if (name === "promises" && typeof v === "object" && v !== null) out = wrapModule(v, `${path}.promises`, cap, key);
        memo.set(name, [v, out]);
        return out;
      },
      // Patches written through a wrapper reach the real module, unwrapped, so a
      // package's wrapper never leaks into code that reads the shared module.
      set(target, name, value: unknown) {
        return ReflectSet(target, name, unwrap(value), target);
      },
      defineProperty(target, name, desc) {
        const d = "value" in desc ? { ...desc, value: unwrap(desc.value) } : desc;
        return ReflectDefineProperty(target, name, d);
      },
    });
    targets.set(proxy, real);
    byKey.set(key, proxy);
    return proxy;
  };

  return { wrapModule, unwrap };
}
