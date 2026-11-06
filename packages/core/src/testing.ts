/**
 * Test helpers: an offline `fetch` that serves recorded registry fixtures, and a
 * {@link RegistryClient} wired to it. Exported as `@depward/core/testing`.
 *
 * Fixture layout (file names replace the `/` in scoped names with `+`):
 *
 * ```
 * <dir>/packuments/<name>.json   GET {registry}/{name}
 * <dir>/downloads/<name>.json    GET https://api.npmjs.org/downloads/point/last-week/{name}
 * <dir>/tarballs/<file>.tgz      GET any URL whose path contains /-/<file>.tgz
 * ```
 *
 * @module
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createMemoryCache } from "./cache.ts";
import { createRegistryClient, type RegistryClient, type RegistryClientOptions } from "./registry/client.ts";
import { NPM_REGISTRY } from "./registry/npmrc.ts";

/** A request seen by a fixture fetch. */
export interface FixtureRequest {
  url: string;
  headers: Record<string, string>;
}

/** A `fetch` replacement that also records the requests it served. */
export interface FixtureFetch {
  fetch: typeof fetch;
  requests: FixtureRequest[];
}

/** Converts a package name to a fixture file stem (`@scope/name` → `@scope+name`). */
export function fixtureFileName(name: string): string {
  return name.replace("/", "+");
}

/**
 * Creates an offline `fetch` backed by fixture files in `dir`. Missing files return 404.
 * Responses carry an `ETag` (sha256 of the file) and honour `If-None-Match` with 304.
 */
export function createFixtureFetch(dir: string): FixtureFetch {
  const requests: FixtureRequest[] = [];
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    requests.push({ url: url.href, headers });

    const file = fixturePath(dir, url);
    if (!file) return new Response("not found", { status: 404 });
    let body: Buffer;
    try {
      body = await readFile(file);
    } catch {
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
    }
    const etag = `"${createHash("sha256").update(body).digest("hex").slice(0, 32)}"`;
    if (headers["if-none-match"] === etag) return new Response(null, { status: 304, headers: { etag } });
    return new Response(new Uint8Array(body), { status: 200, headers: { etag } });
  };
  return { fetch: fetchImpl as typeof fetch, requests };
}

function fixturePath(dir: string, url: URL): string | null {
  const path = decodeURIComponent(url.pathname);
  const tgz = /\/-\/([\w.~-]+\.tgz)$/.exec(path);
  if (tgz?.[1]) return join(dir, "tarballs", tgz[1]);
  const downloads = /^\/downloads\/point\/last-week\/(.+)$/.exec(path);
  if (url.hostname === "api.npmjs.org") {
    return downloads?.[1] ? join(dir, "downloads", `${safeStem(downloads[1])}.json`) : null;
  }
  const name = path.slice(1);
  return name ? join(dir, "packuments", `${safeStem(name)}.json`) : null;
}

function safeStem(name: string): string {
  const stem = fixtureFileName(name);
  if (!/^@?[\w.~+-]+$/.test(stem) || stem.includes("..")) return "__invalid__";
  return stem;
}

/**
 * A {@link RegistryClient} that serves fixtures from `dir`, uses an in-memory cache, and
 * ignores the machine's `.npmrc`. It never touches the network.
 */
export function createFixtureRegistryClient(
  dir: string,
  opts: Omit<RegistryClientOptions, "fetch"> = {},
): RegistryClient & { requests: FixtureRequest[] } {
  const fx = createFixtureFetch(dir);
  const client = createRegistryClient({
    cache: createMemoryCache(),
    npmConfig: { registry: NPM_REGISTRY, scopes: {}, auth: [] },
    ...opts,
    fetch: fx.fetch,
  });
  return Object.assign(client, { requests: fx.requests });
}
