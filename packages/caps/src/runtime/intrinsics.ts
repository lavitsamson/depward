// Intrinsics captured when the runtime layer loads, before any package code runs, so a
// package that later replaces `Reflect.apply` or `WeakMap.prototype.get` can't change
// what the wrappers do (ADR 0007). This covers the per-call paths only; the runtime
// layer is defense in depth, not a sandbox.

export const ReflectApply: typeof Reflect.apply = Reflect.apply;
export const ReflectConstruct: typeof Reflect.construct = Reflect.construct;
export const ReflectGet: typeof Reflect.get = Reflect.get;
export const ReflectSet: typeof Reflect.set = Reflect.set;
export const ReflectDefineProperty: typeof Reflect.defineProperty = Reflect.defineProperty;
export const ReflectGetOwnPropertyDescriptor: typeof Reflect.getOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
export const ReflectOwnKeys: typeof Reflect.ownKeys = Reflect.ownKeys;
export const ProxyCtor: ProxyConstructor = Proxy;
export const ErrorCaptureStackTrace: typeof Error.captureStackTrace = Error.captureStackTrace;

const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakMapHas = WeakMap.prototype.has;
const mapGet = Map.prototype.get;
const mapSet = Map.prototype.set;

/** A WeakMap whose methods are the originals, whatever happens to `WeakMap.prototype`. */
export class SafeWeakMap<K extends WeakKey, V> extends WeakMap<K, V> {
  override get(key: K): V | undefined {
    return ReflectApply(weakMapGet, this, [key]) as V | undefined;
  }
  override set(key: K, value: V): this {
    ReflectApply(weakMapSet, this, [key, value]);
    return this;
  }
  override has(key: K): boolean {
    return ReflectApply(weakMapHas, this, [key]) as boolean;
  }
}

/** A Map whose `get`/`set` are the originals. */
export class SafeMap<K, V> extends Map<K, V> {
  override get(key: K): V | undefined {
    return ReflectApply(mapGet, this, [key]) as V | undefined;
  }
  override set(key: K, value: V): this {
    ReflectApply(mapSet, this, [key, value]);
    return this;
  }
}
