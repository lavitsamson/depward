// .npmrc handling. Format and precedence follow the npm docs:
// https://docs.npmjs.com/cli/v11/configuring-npm/npmrc
//
// Only the settings depward needs are read: `registry`, `@scope:registry`, and the
// registry-scoped credentials `//host/path/:_authToken` and `//host/path/:_auth`.
// The global and built-in npmrc files are not read.

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { Secret } from "../secret.ts";

/** The public npm registry. */
export const NPM_REGISTRY = "https://registry.npmjs.org/";

/** A credential tied to a registry URI prefix such as `//registry.npmjs.org/`. */
export interface RegistryAuth {
  /** Nerf-darted prefix: `//host[:port]/path/`. */
  prefix: string;
  /** Sent as `Authorization: Bearer …` (`_authToken`). */
  token?: Secret;
  /** Sent as `Authorization: Basic …` (`_auth`, already base64). */
  basic?: Secret;
}

/** The parts of npm configuration that depward uses. */
export interface NpmConfig {
  /** Default registry URL, always ending in `/`. */
  registry: string;
  /** Scope (with `@`) to registry URL, each ending in `/`. */
  scopes: Record<string, string>;
  auth: RegistryAuth[];
}

/** Options for {@link loadNpmConfig}. */
export interface LoadNpmConfigOptions {
  cwd?: string;
  env?: Record<string, string | undefined>;
  home?: string;
}

/**
 * Parses `.npmrc` text into raw key/value pairs, expanding `${VAR}` (left as-is when
 * unset) and `${VAR?}` (empty when unset).
 */
export function parseNpmrc(text: string, env: Record<string, string | undefined> = {}): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = expandEnv(line.slice(0, eq).trim(), env);
    let value = line.slice(eq + 1).trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) {
      value = value.slice(1, -1);
    }
    out.set(key, expandEnv(value, env));
  }
  return out;
}

function expandEnv(s: string, env: Record<string, string | undefined>): string {
  return s.replace(/(\\*)\$\{([^}?]+)(\?)?\}/g, (match: string, slashes: string, name: string, optional?: string) => {
    // An odd number of backslashes escapes the expression.
    if (slashes.length % 2 === 1) return match.slice(1);
    const value = env[name];
    if (value !== undefined) return slashes + value;
    return optional ? slashes : match;
  });
}

/** Ensures a registry URL ends with `/`. Throws a `TypeError` for an invalid URL. */
export function normalizeRegistry(url: string): string {
  const u = new URL(url);
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u.href;
}

/** Converts a URL to npm's "nerf dart" form: `//host[:port]/path/` (path up to the last `/`). */
export function nerfDart(url: string): string {
  const u = new URL(url);
  const path = u.pathname.slice(0, u.pathname.lastIndexOf("/") + 1);
  return `//${u.host}${path}`;
}

/** Builds an {@link NpmConfig} from merged key/value pairs (later maps win). */
export function npmConfigFrom(...layers: Map<string, string>[]): NpmConfig {
  const merged = new Map<string, string>();
  for (const layer of layers) for (const [k, v] of layer) merged.set(k, v);

  let registry = NPM_REGISTRY;
  const scopes: Record<string, string> = {};
  const auth = new Map<string, RegistryAuth>();
  for (const [key, value] of merged) {
    if (key === "registry") {
      registry = tryNormalize(value) ?? registry;
    } else if (/^@[^:]+:registry$/.test(key)) {
      const url = tryNormalize(value);
      if (url) scopes[key.slice(0, key.indexOf(":"))] = url;
    } else if (key.startsWith("//")) {
      const sep = key.lastIndexOf(":");
      if (sep < 0 || value === "") continue;
      const field = key.slice(sep + 1);
      const prefix = withSlash(key.slice(0, sep));
      const entry = auth.get(prefix) ?? { prefix };
      if (field === "_authToken") entry.token = new Secret(value);
      else if (field === "_auth") entry.basic = new Secret(value);
      else continue;
      auth.set(prefix, entry);
    }
  }
  return { registry, scopes, auth: [...auth.values()] };
}

function withSlash(prefix: string): string {
  return prefix.endsWith("/") ? prefix : `${prefix}/`;
}

function tryNormalize(url: string): string | undefined {
  try {
    return normalizeRegistry(url);
  } catch {
    return undefined;
  }
}

/**
 * Loads npm configuration from the user's `.npmrc` (`$NPM_CONFIG_USERCONFIG` or
 * `~/.npmrc`), then the project's `.npmrc` in `cwd`, then `npm_config_registry`.
 * Missing files are ignored.
 */
export async function loadNpmConfig(opts: LoadNpmConfigOptions = {}): Promise<NpmConfig> {
  const env = opts.env ?? process.env;
  const cwd = opts.cwd ?? process.cwd();
  const userFile = envValue(env, "npm_config_userconfig") ?? join(opts.home ?? homedir(), ".npmrc");
  const layers = [await readNpmrc(userFile, env), await readNpmrc(join(cwd, ".npmrc"), env)];
  const envRegistry = envValue(env, "npm_config_registry");
  if (envRegistry) layers.push(new Map([["registry", envRegistry]]));
  return npmConfigFrom(...layers);
}

function envValue(env: Record<string, string | undefined>, lowerName: string): string | undefined {
  return env[lowerName] ?? env[lowerName.toUpperCase()];
}

async function readNpmrc(path: string, env: Record<string, string | undefined>): Promise<Map<string, string>> {
  try {
    return parseNpmrc(await readFile(path, "utf8"), env);
  } catch {
    return new Map();
  }
}

/** Picks the registry for a package name, honouring `@scope:registry`. */
export function registryFor(config: NpmConfig, name: string): string {
  if (name.startsWith("@")) {
    const scope = name.slice(0, name.indexOf("/"));
    const url = config.scopes[scope];
    if (url) return url;
  }
  return config.registry;
}

/**
 * Returns the `Authorization` header for a request URL, or `undefined`. Credentials are
 * only matched by `//host/path/` prefix, so they are never sent to another host.
 */
export function authHeaderFor(config: NpmConfig, url: string): string | undefined {
  let dart: string;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" && u.protocol !== "http:") return undefined;
    dart = `//${u.host}${u.pathname}`;
  } catch {
    return undefined;
  }
  let best: RegistryAuth | undefined;
  for (const entry of config.auth) {
    if (dart.startsWith(entry.prefix) && (!best || entry.prefix.length > best.prefix.length)) best = entry;
  }
  if (best?.token) return `Bearer ${best.token.reveal()}`;
  if (best?.basic) return `Basic ${best.basic.reveal()}`;
  return undefined;
}
