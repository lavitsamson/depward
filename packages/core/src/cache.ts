import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

/** One cached HTTP body plus the data needed to revalidate it. */
export interface CacheEntry {
  body: Uint8Array;
  /** The response `ETag`, used for `If-None-Match` revalidation. */
  etag?: string;
  /** When the entry was stored or last revalidated (ms since the epoch). */
  storedAt: number;
}

/**
 * A key/value store for registry responses. `namespace` is a short fixed word such as
 * `packument` or `tarball`; `key` is any string. Implementations must treat a corrupt
 * entry as a miss, and `set` must never leave a half-written entry visible.
 */
export interface Cache {
  get(namespace: string, key: string): Promise<CacheEntry | null>;
  set(namespace: string, key: string, entry: CacheEntry): Promise<void>;
}

/** An in-process cache. Useful for tests and short-lived tools. */
export function createMemoryCache(): Cache {
  const store = new Map<string, CacheEntry>();
  return {
    async get(namespace, key) {
      const e = store.get(`${namespace}\0${key}`);
      return e ? { ...e, body: e.body.slice() } : null;
    },
    async set(namespace, key, entry) {
      store.set(`${namespace}\0${key}`, { ...entry, body: entry.body.slice() });
    },
  };
}

/**
 * The cache directory: `$DEPWARD_CACHE_DIR`, else `$XDG_CACHE_HOME/depward`, else the
 * platform default (`%LOCALAPPDATA%\depward\Cache`, `~/Library/Caches/depward`, or
 * `~/.cache/depward`).
 */
export function defaultCacheDir(
  env: Record<string, string | undefined> = process.env,
  platform: NodeJS.Platform = process.platform,
  home: string = homedir(),
): string {
  if (env["DEPWARD_CACHE_DIR"]) return env["DEPWARD_CACHE_DIR"];
  if (env["XDG_CACHE_HOME"]) return join(env["XDG_CACHE_HOME"], "depward");
  if (platform === "win32") return join(env["LOCALAPPDATA"] ?? join(home, "AppData", "Local"), "depward", "Cache");
  if (platform === "darwin") return join(home, "Library", "Caches", "depward");
  return join(home, ".cache", "depward");
}

// On-disk format: one JSON header line (`{"v":1,"etag":…,"storedAt":…}`), "\n", raw body.
// JSON.stringify never emits a raw newline, so the first "\n" always ends the header.
const NEWLINE = 0x0a;

/**
 * A disk cache with one file per entry at `<dir>/<namespace>/<sha256(key)>`. Writes go
 * to a temp file that is then renamed into place, so concurrent processes see either the
 * old entry or the new one, never a partial file.
 */
export function createDiskCache(dir: string = defaultCacheDir()): Cache {
  const fileFor = (namespace: string, key: string): string => {
    if (!/^[a-z0-9-]+$/.test(namespace)) throw new TypeError("cache namespace must match [a-z0-9-]+");
    return join(dir, namespace, createHash("sha256").update(key).digest("hex"));
  };
  return {
    async get(namespace, key) {
      let raw: Buffer;
      try {
        raw = await readFile(fileFor(namespace, key));
      } catch {
        return null;
      }
      const nl = raw.indexOf(NEWLINE);
      if (nl < 0) return null;
      try {
        const header: unknown = JSON.parse(raw.subarray(0, nl).toString("utf8"));
        if (typeof header !== "object" || header === null) return null;
        const h = header as { v?: unknown; etag?: unknown; storedAt?: unknown };
        if (h.v !== 1 || typeof h.storedAt !== "number") return null;
        const entry: CacheEntry = { body: new Uint8Array(raw.subarray(nl + 1)), storedAt: h.storedAt };
        if (typeof h.etag === "string") entry.etag = h.etag;
        return entry;
      } catch {
        return null;
      }
    },
    async set(namespace, key, entry) {
      const file = fileFor(namespace, key);
      await mkdir(join(dir, namespace), { recursive: true });
      const header = JSON.stringify({ v: 1, etag: entry.etag, storedAt: entry.storedAt });
      const tmp = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
      // Mode 0o600: cached packuments may come from a private registry.
      await writeFile(tmp, Buffer.concat([Buffer.from(`${header}\n`, "utf8"), entry.body]), { mode: 0o600 });
      try {
        await rename(tmp, file);
      } catch {
        // On Windows, rename fails if another process holds the target open. That process
        // wrote an equivalent entry, so dropping ours is fine.
        await rm(tmp, { force: true });
      }
    },
  };
}
