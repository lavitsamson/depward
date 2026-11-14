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

// The decision path (attribution, policy, the module hooks) runs while package code is
// loaded, so everything it calls is captured here too: string methods, JSON, URI
// coding, Object.hasOwn, Object.keys, RegExp exec. Callers avoid array methods and
// for…of over arrays (Array.prototype and the array iterator can be replaced), and
// String split/replace (they consult Symbol.split/Symbol.replace on String.prototype).
export const ObjectHasOwn: typeof Object.hasOwn = Object.hasOwn;
export const ObjectKeys: typeof Object.keys = Object.keys;
export const JSONParse: typeof JSON.parse = JSON.parse;
export const JSONStringify: typeof JSON.stringify = JSON.stringify;
export const DecodeURIComponent: typeof decodeURIComponent = decodeURIComponent;
export const EncodeURIComponent: typeof encodeURIComponent = encodeURIComponent;

const strStartsWith = String.prototype.startsWith;
const strEndsWith = String.prototype.endsWith;
const strSlice = String.prototype.slice;
const strIndexOf = String.prototype.indexOf;
const strLastIndexOf = String.prototype.lastIndexOf;
const strToLowerCase = String.prototype.toLowerCase;
const regExpExec = RegExp.prototype.exec;

export const StringStartsWith = (s: string, search: string): boolean => ReflectApply(strStartsWith, s, [search]) as boolean;
export const StringEndsWith = (s: string, search: string): boolean => ReflectApply(strEndsWith, s, [search]) as boolean;
export const StringSlice = (s: string, start: number, end?: number): string => ReflectApply(strSlice, s, end === undefined ? [start] : [start, end]) as string;
export const StringIndexOf = (s: string, search: string, from = 0): number => ReflectApply(strIndexOf, s, [search, from]) as number;
export const StringLastIndexOf = (s: string, search: string): number => ReflectApply(strLastIndexOf, s, [search]) as number;
export const StringToLowerCase = (s: string): string => ReflectApply(strToLowerCase, s, []) as string;
/** `re.exec(s)` with the original exec. */
export const RegExpExec = (re: RegExp, s: string): RegExpExecArray | null => ReflectApply(regExpExec, re, [s]) as RegExpExecArray | null;

/** `s` with every `\` turned into `/`, without String.prototype.replaceAll. */
export function toSlashes(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) out += s[i] === "\\" ? "/" : s[i];
  return out;
}

const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakMapHas = WeakMap.prototype.has;
const mapGet = Map.prototype.get;
const mapSet = Map.prototype.set;
const setHas = Set.prototype.has;
const setAdd = Set.prototype.add;

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

/** A Set whose `has`/`add` are the originals. Fill it with `add` (the constructor uses the iterator). */
export class SafeSet<T> extends Set<T> {
  override has(value: T): boolean {
    return ReflectApply(setHas, this, [value]) as boolean;
  }
  override add(value: T): this {
    ReflectApply(setAdd, this, [value]);
    return this;
  }
}
