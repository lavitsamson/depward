// depward configuration: `depward.config.json`, or the `"depward"` key in package.json.
// Spec: docs/specs/core.md §Config. JSON only, so no parser dependency.
//
// Core validates the shape and nothing more. What the actions *mean* (defaults,
// escalations, list matching) is the policy engine's job in `@depward/gate`.

import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { DepwardError, isDepwardError } from "./errors.ts";

/** What to do with a package: install it, ask the user first, or refuse. */
export type PolicyAction = "allow" | "ask" | "deny";

/** Every {@link PolicyAction}, least to most severe. */
export const POLICY_ACTIONS: readonly PolicyAction[] = ["allow", "ask", "deny"];

/** Age and popularity thresholds for the registry checks. */
export interface ConfigThresholds {
  /** `version-too-new` below this age in days. */
  minVersionAgeDays?: number;
  /** `package-too-new` below this age in days. */
  minPackageAgeDays?: number;
  /** `low-downloads` below this many weekly downloads. */
  minWeeklyDownloads?: number;
}

/** A validated depward configuration. Missing fields hold their defaults. */
export interface DepwardConfig {
  /** Action overrides per finding ID. Default `{}`. */
  readonly policy: Readonly<Record<string, PolicyAction>>;
  /** Default `{}` (each check uses its own default). */
  readonly thresholds: Readonly<ConfigThresholds>;
  /** Packages that are always allowed: name globs (`@myorg/*`) or exact `name@version`. */
  readonly allow: readonly string[];
  /** Packages that are always denied: name globs or exact `name@version`. Wins over `allow`. */
  readonly deny: readonly string[];
  /** Action when a lookup fails (network, timeout, offline). Default `"ask"`. */
  readonly onError: PolicyAction;
  /** Registry URL override. Default: from `.npmrc`. */
  readonly registry?: string;
  /** The file the config came from, or `null` for the built-in defaults. */
  readonly source: string | null;
}

/** Options for {@link loadConfig}. */
export interface LoadConfigOptions {
  /** Read this file instead of looking in `cwd` (`--config <path>`). A `package.json` is read from its `"depward"` key. */
  path?: string;
}

/** The config file name looked up in the project directory. */
export const CONFIG_FILE = "depward.config.json";

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_LIST = 10_000;
const KEYS = new Set(["$schema", "policy", "thresholds", "allow", "deny", "onError", "registry"]);
const THRESHOLDS = new Set(["minVersionAgeDays", "minPackageAgeDays", "minWeeklyDownloads"]);
const FINDING_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** The configuration used when no file is found. */
export function defaultConfig(): DepwardConfig {
  return { policy: {}, thresholds: {}, allow: [], deny: [], onError: "ask", source: null };
}

function invalid(source: string, message: string): DepwardError {
  return new DepwardError("INVALID_CONFIG", `${source}: ${message}`);
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isAction = (v: unknown): v is PolicyAction => typeof v === "string" && (POLICY_ACTIONS as readonly string[]).includes(v);

function list(value: unknown, field: string, source: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw invalid(source, `"${field}" must be an array of strings`);
  if (value.length > MAX_LIST) throw invalid(source, `"${field}" has more than ${MAX_LIST} entries`);
  return value.map((entry, i) => {
    if (typeof entry !== "string" || entry.trim() === "") throw invalid(source, `"${field}[${i}]" must be a non-empty string`);
    return entry.trim();
  });
}

/**
 * Validates a parsed config object. Unknown keys are errors, not warnings: a typo such
 * as `"denny"` must not silently disable a deny list.
 *
 * @param value - the parsed JSON (the whole file, or package.json's `"depward"` value)
 * @param source - where it came from, for error messages and {@link DepwardConfig.source}
 * @throws DepwardError `INVALID_CONFIG`
 */
export function parseConfig(value: unknown, source: string): DepwardConfig {
  if (!isObject(value)) throw invalid(source, "the config must be a JSON object");
  for (const key of Object.keys(value)) {
    if (!KEYS.has(key)) throw invalid(source, `unknown key ${JSON.stringify(key)}`);
  }

  const policy: Record<string, PolicyAction> = {};
  if (value["policy"] !== undefined) {
    if (!isObject(value["policy"])) throw invalid(source, `"policy" must be an object of finding ID → action`);
    for (const [id, action] of Object.entries(value["policy"])) {
      if (!FINDING_ID.test(id)) throw invalid(source, `"policy" key ${JSON.stringify(id)} is not a finding ID`);
      if (!isAction(action)) throw invalid(source, `"policy.${id}" must be "allow", "ask", or "deny"`);
      policy[id] = action;
    }
  }

  const thresholds: ConfigThresholds = {};
  if (value["thresholds"] !== undefined) {
    if (!isObject(value["thresholds"])) throw invalid(source, `"thresholds" must be an object`);
    for (const [key, n] of Object.entries(value["thresholds"])) {
      if (!THRESHOLDS.has(key)) throw invalid(source, `unknown threshold ${JSON.stringify(key)}`);
      if (typeof n !== "number" || !Number.isFinite(n) || n < 0) throw invalid(source, `"thresholds.${key}" must be a number ≥ 0`);
      thresholds[key as keyof ConfigThresholds] = n;
    }
  }

  const onError = value["onError"] ?? "ask";
  if (!isAction(onError)) throw invalid(source, `"onError" must be "allow", "ask", or "deny"`);

  const config: DepwardConfig = {
    policy,
    thresholds,
    allow: list(value["allow"], "allow", source),
    deny: list(value["deny"], "deny", source),
    onError,
    source,
  };

  const registry = value["registry"];
  if (registry === undefined) return config;
  let url: URL | null = null;
  try {
    url = typeof registry === "string" ? new URL(registry) : null;
  } catch {
    url = null;
  }
  if (url === null || (url.protocol !== "https:" && url.protocol !== "http:")) {
    throw invalid(source, `"registry" must be an http(s) URL`);
  }
  return { ...config, registry: url.href };
}

async function readJson(path: string): Promise<unknown> {
  let text: string;
  try {
    const bytes = await readFile(path);
    if (bytes.byteLength > MAX_CONFIG_BYTES) throw invalid(path, `larger than ${MAX_CONFIG_BYTES} bytes`);
    text = bytes.toString("utf8");
  } catch (err) {
    if (isDepwardError(err)) throw err;
    if ((err as NodeJS.ErrnoException).code === "ENOENT") throw new DepwardError("NOT_FOUND", `${path}: no such file`, { cause: err });
    throw invalid(path, "can't be read");
  }
  try {
    return JSON.parse(text.replace(/^﻿/, ""));
  } catch (cause) {
    throw new DepwardError("INVALID_CONFIG", `${path}: not valid JSON`, { cause });
  }
}

async function fromPackageJson(path: string, required: boolean): Promise<DepwardConfig | null> {
  const pkg = await readJson(path);
  const section = isObject(pkg) ? pkg["depward"] : undefined;
  if (section === undefined) {
    if (required) throw invalid(path, `has no "depward" key`);
    return null;
  }
  return parseConfig(section, `${path} ("depward" key)`);
}

const missing = (err: unknown): boolean => isDepwardError(err, "NOT_FOUND");

/**
 * Loads the project's config: `depward.config.json` in `cwd`, else the `"depward"` key
 * of `cwd/package.json`, else {@link defaultConfig}. Only `cwd` is searched, not its
 * parents, so the config that applies is always the one next to the project.
 *
 * @throws DepwardError `INVALID_CONFIG` for a malformed file, `NOT_FOUND` for a missing `opts.path`
 */
export async function loadConfig(cwd: string, opts: LoadConfigOptions = {}): Promise<DepwardConfig> {
  if (opts.path !== undefined) {
    const path = resolve(cwd, opts.path);
    if (basename(path) === "package.json") return (await fromPackageJson(path, true)) as DepwardConfig;
    return parseConfig(await readJson(path), path);
  }

  const file = join(cwd, CONFIG_FILE);
  try {
    return parseConfig(await readJson(file), file);
  } catch (err) {
    if (!missing(err)) throw err;
  }
  try {
    return (await fromPackageJson(join(cwd, "package.json"), false)) ?? defaultConfig();
  } catch (err) {
    if (missing(err)) return defaultConfig();
    throw err;
  }
}
