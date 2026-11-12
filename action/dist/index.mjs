import { builtinModules, createRequire } from "node:module";
import { appendFile, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, join, posix, resolve } from "node:path";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { gunzipSync, gzip } from "node:zlib";
import { execFile } from "node:child_process";
import { isIP } from "node:net";
import { promisify } from "node:util";
// \0rolldown/runtime.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esmMin = (fn, res, err) => () => {
	if (err) throw err[0];
	try {
		return fn && (res = fn(fn = 0)), res;
	} catch (e) {
		throw err = [e], e;
	}
};
var __commonJSMin = (cb, mod) => () => (mod || (cb((mod = { exports: {} }).exports, mod, mod.exports), cb = null), mod.exports);
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default") ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
var __require = /* #__PURE__ */ (() => createRequire(import.meta.url))();
// ../packages/core/src/errors.ts
/** Type guard for {@link DepwardError}, optionally checking for a specific code. */
function isDepwardError(value, code) {
	return value instanceof DepwardError && (code === void 0 || value.code === code);
}
var DepwardError;
var init_errors = __esmMin((() => {
	DepwardError = class extends Error {
		name = "DepwardError";
		code;
		constructor(code, message, options) {
			super(message, options);
			this.code = code;
		}
	};
}));
// ../packages/core/src/findings.ts
/** Sort comparator: most severe first. */
function compareSeverity(a, b) {
	return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
}
function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}
/** Sort comparator giving deterministic output: severity, then package, then id. */
function compareFindings(a, b) {
	return compareSeverity(a.severity, b.severity) || compareStrings(a.package, b.package) || compareStrings(a.id, b.id);
}
/** Documentation URL for a finding ID (its entry in `docs/findings.md`). */
function findingDocsUrl(id) {
	return `https://github.com/lavitsamson/depward/blob/main/docs/findings.md#${id}`;
}
var SEVERITIES;
var init_findings = __esmMin((() => {
	SEVERITIES = [
		"critical",
		"high",
		"medium",
		"low",
		"info"
	];
}));
// ../packages/core/src/secret.ts
/** Removes any `user:password@` part from a URL so it is safe to put in a message. */
function redactUrl(url) {
	try {
		const u = new URL(url);
		if (u.username || u.password) {
			u.username = "";
			u.password = "";
		}
		return u.href;
	} catch {
		return "<invalid url>";
	}
}
var REDACTED, Secret;
var init_secret = __esmMin((() => {
	REDACTED = "[redacted]";
	Secret = class {
		#value;
		constructor(value) {
			this.#value = value;
		}
		/** Returns the raw credential. Never pass the result to a logger. */
		reveal() {
			return this.#value;
		}
		toString() {
			return REDACTED;
		}
		toJSON() {
			return REDACTED;
		}
	};
	Object.defineProperty(Secret.prototype, Symbol.for("nodejs.util.inspect.custom"), { value: () => REDACTED });
}));
// ../packages/core/src/config.ts
/** The configuration used when no file is found. */
function defaultConfig() {
	return {
		policy: {},
		thresholds: {},
		allow: [],
		deny: [],
		onError: "ask",
		source: null
	};
}
function invalid$2(source, message) {
	return new DepwardError("INVALID_CONFIG", `${source}: ${message}`);
}
function list$1(value, field, source) {
	if (value === void 0) return [];
	if (!Array.isArray(value)) throw invalid$2(source, `"${field}" must be an array of strings`);
	if (value.length > MAX_LIST) throw invalid$2(source, `"${field}" has more than ${MAX_LIST} entries`);
	return value.map((entry, i) => {
		if (typeof entry !== "string" || entry.trim() === "") throw invalid$2(source, `"${field}[${i}]" must be a non-empty string`);
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
function parseConfig(value, source) {
	if (!isObject$1(value)) throw invalid$2(source, "the config must be a JSON object");
	for (const key of Object.keys(value)) if (!KEYS.has(key)) throw invalid$2(source, `unknown key ${JSON.stringify(key)}`);
	const policy = {};
	if (value["policy"] !== void 0) {
		if (!isObject$1(value["policy"])) throw invalid$2(source, `"policy" must be an object of finding ID → action`);
		for (const [id, action] of Object.entries(value["policy"])) {
			if (!FINDING_ID.test(id)) throw invalid$2(source, `"policy" key ${JSON.stringify(id)} is not a finding ID`);
			if (!isAction(action)) throw invalid$2(source, `"policy.${id}" must be "allow", "ask", or "deny"`);
			policy[id] = action;
		}
	}
	const thresholds = {};
	if (value["thresholds"] !== void 0) {
		if (!isObject$1(value["thresholds"])) throw invalid$2(source, `"thresholds" must be an object`);
		for (const [key, n] of Object.entries(value["thresholds"])) {
			if (!THRESHOLDS.has(key)) throw invalid$2(source, `unknown threshold ${JSON.stringify(key)}`);
			if (typeof n !== "number" || !Number.isFinite(n) || n < 0) throw invalid$2(source, `"thresholds.${key}" must be a number ≥ 0`);
			thresholds[key] = n;
		}
	}
	const onError = value["onError"] ?? "ask";
	if (!isAction(onError)) throw invalid$2(source, `"onError" must be "allow", "ask", or "deny"`);
	const config = {
		policy,
		thresholds,
		allow: list$1(value["allow"], "allow", source),
		deny: list$1(value["deny"], "deny", source),
		onError,
		source
	};
	const registry = value["registry"];
	if (registry === void 0) return config;
	let url = null;
	try {
		url = typeof registry === "string" ? new URL(registry) : null;
	} catch {
		url = null;
	}
	if (url === null || url.protocol !== "https:" && url.protocol !== "http:") throw invalid$2(source, `"registry" must be an http(s) URL`);
	return {
		...config,
		registry: url.href
	};
}
async function readJson$1(path) {
	let text;
	try {
		const bytes = await readFile(path);
		if (bytes.byteLength > MAX_CONFIG_BYTES) throw invalid$2(path, `larger than ${MAX_CONFIG_BYTES} bytes`);
		text = bytes.toString("utf8");
	} catch (err) {
		if (isDepwardError(err)) throw err;
		if (err.code === "ENOENT") throw new DepwardError("NOT_FOUND", `${path}: no such file`, { cause: err });
		throw invalid$2(path, "can't be read");
	}
	try {
		return JSON.parse(text.replace(/^﻿/, ""));
	} catch (cause) {
		throw new DepwardError("INVALID_CONFIG", `${path}: not valid JSON`, { cause });
	}
}
async function fromPackageJson(path, required) {
	const pkg = await readJson$1(path);
	const section = isObject$1(pkg) ? pkg["depward"] : void 0;
	if (section === void 0) {
		if (required) throw invalid$2(path, `has no "depward" key`);
		return null;
	}
	return parseConfig(section, `${path} ("depward" key)`);
}
/**
* Loads the project's config: `depward.config.json` in `cwd`, else the `"depward"` key
* of `cwd/package.json`, else {@link defaultConfig}. Only `cwd` is searched, not its
* parents, so the config that applies is always the one next to the project.
*
* @throws DepwardError `INVALID_CONFIG` for a malformed file, `NOT_FOUND` for a missing `opts.path`
*/
async function loadConfig(cwd, opts = {}) {
	if (opts.path !== void 0) {
		const path = resolve(cwd, opts.path);
		if (basename(path) === "package.json") return await fromPackageJson(path, true);
		return parseConfig(await readJson$1(path), path);
	}
	const file = join(cwd, CONFIG_FILE);
	try {
		return parseConfig(await readJson$1(file), file);
	} catch (err) {
		if (!missing(err)) throw err;
	}
	try {
		return await fromPackageJson(join(cwd, "package.json"), false) ?? defaultConfig();
	} catch (err) {
		if (missing(err)) return defaultConfig();
		throw err;
	}
}
var POLICY_ACTIONS, CONFIG_FILE, MAX_CONFIG_BYTES, MAX_LIST, KEYS, THRESHOLDS, FINDING_ID, isObject$1, isAction, missing;
var init_config = __esmMin((() => {
	init_errors();
	POLICY_ACTIONS = [
		"allow",
		"ask",
		"deny"
	];
	CONFIG_FILE = "depward.config.json";
	MAX_CONFIG_BYTES = 1048576;
	MAX_LIST = 1e4;
	KEYS = /* @__PURE__ */ new Set([
		"$schema",
		"policy",
		"thresholds",
		"allow",
		"deny",
		"onError",
		"registry"
	]);
	THRESHOLDS = /* @__PURE__ */ new Set([
		"minVersionAgeDays",
		"minPackageAgeDays",
		"minWeeklyDownloads"
	]);
	FINDING_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
	isObject$1 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
	isAction = (v) => typeof v === "string" && POLICY_ACTIONS.includes(v);
	missing = (err) => isDepwardError(err, "NOT_FOUND");
}));
// ../packages/core/src/cache.ts
/**
* The cache directory: `$DEPWARD_CACHE_DIR`, else `$XDG_CACHE_HOME/depward`, else the
* platform default (`%LOCALAPPDATA%\depward\Cache`, `~/Library/Caches/depward`, or
* `~/.cache/depward`).
*/
function defaultCacheDir(env = process.env, platform = process.platform, home = homedir()) {
	if (env["DEPWARD_CACHE_DIR"]) return env["DEPWARD_CACHE_DIR"];
	if (env["XDG_CACHE_HOME"]) return join(env["XDG_CACHE_HOME"], "depward");
	if (platform === "win32") return join(env["LOCALAPPDATA"] ?? join(home, "AppData", "Local"), "depward", "Cache");
	if (platform === "darwin") return join(home, "Library", "Caches", "depward");
	return join(home, ".cache", "depward");
}
/**
* A disk cache with one file per entry at `<dir>/<namespace>/<sha256(key)>`. Writes go
* to a temp file that is then renamed into place, so concurrent processes see either the
* old entry or the new one, never a partial file.
*/
function createDiskCache(dir = defaultCacheDir()) {
	const fileFor = (namespace, key) => {
		if (!/^[a-z0-9-]+$/.test(namespace)) throw new TypeError("cache namespace must match [a-z0-9-]+");
		return join(dir, namespace, createHash("sha256").update(key).digest("hex"));
	};
	return {
		async get(namespace, key) {
			let raw;
			try {
				raw = await readFile(fileFor(namespace, key));
			} catch {
				return null;
			}
			const nl = raw.indexOf(NEWLINE);
			if (nl < 0) return null;
			try {
				const header = JSON.parse(raw.subarray(0, nl).toString("utf8"));
				if (typeof header !== "object" || header === null) return null;
				const h = header;
				if (h.v !== 1 || typeof h.storedAt !== "number") return null;
				const entry = {
					body: new Uint8Array(raw.subarray(nl + 1)),
					storedAt: h.storedAt
				};
				if (typeof h.etag === "string") entry.etag = h.etag;
				return entry;
			} catch {
				return null;
			}
		},
		async set(namespace, key, entry) {
			const file = fileFor(namespace, key);
			await mkdir(join(dir, namespace), { recursive: true });
			const header = JSON.stringify({
				v: 1,
				etag: entry.etag,
				storedAt: entry.storedAt
			});
			const tmp = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
			await writeFile(tmp, Buffer.concat([Buffer.from(`${header}\n`, "utf8"), entry.body]), { mode: 384 });
			try {
				await rename(tmp, file);
			} catch {
				await rm(tmp, { force: true });
			}
		}
	};
}
var NEWLINE;
var init_cache = __esmMin((() => {
	NEWLINE = 10;
}));
// ../packages/core/src/integrity.ts
/** The strongest supported hash in an SRI string, or `null` when there is none. */
function strongestHash(integrity) {
	let best = null;
	for (const token of integrity.trim().split(/\s+/)) {
		const dash = token.indexOf("-");
		if (dash < 0) continue;
		const algorithm = token.slice(0, dash);
		if (!Object.hasOwn(STRENGTH, algorithm)) continue;
		const alg = algorithm;
		const digest = token.slice(dash + 1).split("?")[0] ?? "";
		if (!best || STRENGTH[alg] > STRENGTH[best.algorithm]) best = {
			algorithm: alg,
			digest
		};
	}
	return best;
}
/**
* Verifies bytes against `dist.integrity` (strongest of sha512/sha384/sha256), falling back
* to the legacy sha1 `dist.shasum` only for old versions published without `integrity`.
* Throws `INTEGRITY_MISMATCH` on mismatch or when nothing usable is present.
*/
function verifyIntegrity(bytes, dist) {
	const sri = dist.integrity ? strongestHash(dist.integrity) : null;
	if (sri) {
		const expected = Buffer.from(sri.digest, "base64");
		const actual = createHash(sri.algorithm).update(bytes).digest();
		if (expected.length === actual.length && timingSafeEqual(expected, actual)) return;
		throw new DepwardError("INTEGRITY_MISMATCH", `tarball does not match its ${sri.algorithm} integrity`);
	}
	if (dist.shasum && /^[0-9a-f]{40}$/i.test(dist.shasum)) {
		if (createHash("sha1").update(bytes).digest("hex") === dist.shasum.toLowerCase()) return;
		throw new DepwardError("INTEGRITY_MISMATCH", "tarball does not match its sha1 shasum");
	}
	throw new DepwardError("INTEGRITY_MISMATCH", "version has no usable integrity hash");
}
/** Every `algorithm → base64 digest` in an SRI string, including legacy sha1. */
function hashes(integrity) {
	const out = /* @__PURE__ */ new Map();
	for (const token of integrity.trim().split(/\s+/)) {
		const dash = token.indexOf("-");
		if (dash < 0) continue;
		const algorithm = token.slice(0, dash);
		if (algorithm in STRENGTH || algorithm === "sha1") out.set(algorithm, token.slice(dash + 1).split("?")[0] ?? "");
	}
	return out;
}
/**
* Compares a lockfile's SRI string with a version's `dist`: `true` when they agree,
* `false` when they share a hash algorithm and the digests differ, `null` when they
* have nothing comparable. A lockfile `sha1-` value is also compared with the hex
* `dist.shasum`.
*/
function compareIntegrity(integrity, dist) {
	const lock = hashes(integrity);
	const reg = typeof dist.integrity === "string" ? hashes(dist.integrity) : /* @__PURE__ */ new Map();
	if (typeof dist.shasum === "string" && /^[0-9a-f]{40}$/i.test(dist.shasum) && !reg.has("sha1")) reg.set("sha1", Buffer.from(dist.shasum, "hex").toString("base64"));
	let compared = false;
	for (const [algorithm, digest] of lock) {
		const other = reg.get(algorithm);
		if (other === void 0) continue;
		if (Buffer.from(digest, "base64").toString("base64") !== Buffer.from(other, "base64").toString("base64")) return false;
		compared = true;
	}
	return compared ? true : null;
}
var STRENGTH;
var init_integrity = __esmMin((() => {
	init_errors();
	STRENGTH = {
		sha512: 3,
		sha384: 2,
		sha256: 1
	};
}));
// ../packages/core/src/registry/http.ts
/**
* GET a URL with a timeout covering the whole exchange (headers and body), a body-size
* cap, and manual redirect handling. Only `http:` and `https:` URLs are allowed, because
* URLs such as tarball locations come from untrusted registry metadata.
*/
async function httpGet(url, opts) {
	const signal = AbortSignal.timeout(opts.timeoutMs);
	const maxRedirects = opts.maxRedirects ?? 5;
	let current = url;
	try {
		for (let hop = 0;; hop++) {
			assertHttpUrl(current);
			const headers = new Headers(opts.headers);
			const auth = opts.authFor?.(current);
			if (auth) headers.set("authorization", auth);
			const res = await opts.fetch(current, {
				headers,
				signal,
				redirect: "manual"
			});
			if (res.status >= 300 && res.status < 400 && res.status !== 304) {
				await res.body?.cancel();
				const location = res.headers.get("location");
				if (!location) throw new DepwardError("INVALID_RESPONSE", `redirect without location from ${redactUrl(current)}`);
				if (hop >= maxRedirects) throw new DepwardError("NETWORK", `too many redirects from ${redactUrl(url)}`);
				current = new URL(location, current).href;
				continue;
			}
			const body = await readBody(res, opts.maxBytes, current);
			return {
				status: res.status,
				headers: res.headers,
				body,
				url: current
			};
		}
	} catch (err) {
		if (err instanceof DepwardError) throw err;
		if (signal.aborted) throw new DepwardError("TIMEOUT", `request to ${redactUrl(current)} timed out after ${opts.timeoutMs} ms`, { cause: err });
		throw new DepwardError("NETWORK", `request to ${redactUrl(current)} failed`, { cause: err });
	}
}
function assertHttpUrl(url) {
	let protocol;
	try {
		protocol = new URL(url).protocol;
	} catch (cause) {
		throw new DepwardError("INVALID_ARGUMENT", "invalid URL", { cause });
	}
	if (protocol !== "https:" && protocol !== "http:") throw new DepwardError("INVALID_ARGUMENT", `refusing to fetch a ${protocol} URL`);
}
async function readBody(res, maxBytes, url) {
	const tooBig = () => new DepwardError("LIMIT_EXCEEDED", `response from ${redactUrl(url)} is larger than ${maxBytes} bytes`);
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > maxBytes) {
		await res.body?.cancel();
		throw tooBig();
	}
	if (!res.body) return /* @__PURE__ */ new Uint8Array(0);
	const chunks = [];
	let total = 0;
	const reader = res.body.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel();
			throw tooBig();
		}
		chunks.push(value);
	}
	const out = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.byteLength;
	}
	return out;
}
/** Parses a JSON body, converting failures into an `INVALID_RESPONSE` error. */
function parseJson(body, what) {
	try {
		return JSON.parse(new TextDecoder().decode(body));
	} catch (cause) {
		throw new DepwardError("INVALID_RESPONSE", `${what} is not valid JSON`, { cause });
	}
}
var init_http = __esmMin((() => {
	init_errors();
	init_secret();
}));
// ../packages/core/src/registry/npmrc.ts
/**
* Parses `.npmrc` text into raw key/value pairs, expanding `${VAR}` (left as-is when
* unset) and `${VAR?}` (empty when unset).
*/
function parseNpmrc(text, env = {}) {
	const out = /* @__PURE__ */ new Map();
	for (const raw of text.split(/\r?\n/)) {
		const line = raw.trim();
		if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
		const eq = line.indexOf("=");
		if (eq <= 0) continue;
		const key = expandEnv(line.slice(0, eq).trim(), env);
		let value = line.slice(eq + 1).trim();
		if (value.length >= 2 && (value[0] === "\"" || value[0] === "'") && value.at(-1) === value[0]) value = value.slice(1, -1);
		out.set(key, expandEnv(value, env));
	}
	return out;
}
function expandEnv(s, env) {
	return s.replace(/(\\*)\$\{([^}?]+)(\?)?\}/g, (match, slashes, name, optional) => {
		if (slashes.length % 2 === 1) return match.slice(1);
		const value = env[name];
		if (value !== void 0) return slashes + value;
		return optional ? slashes : match;
	});
}
/** Ensures a registry URL ends with `/`. Throws a `TypeError` for an invalid URL. */
function normalizeRegistry(url) {
	const u = new URL(url);
	if (!u.pathname.endsWith("/")) u.pathname += "/";
	return u.href;
}
/** Converts a URL to npm's "nerf dart" form: `//host[:port]/path/` (path up to the last `/`). */
function nerfDart(url) {
	const u = new URL(url);
	const path = u.pathname.slice(0, u.pathname.lastIndexOf("/") + 1);
	return `//${u.host}${path}`;
}
/** Builds an {@link NpmConfig} from merged key/value pairs (later maps win). */
function npmConfigFrom(...layers) {
	const merged = /* @__PURE__ */ new Map();
	for (const layer of layers) for (const [k, v] of layer) merged.set(k, v);
	let registry = NPM_REGISTRY;
	const scopes = {};
	const auth = /* @__PURE__ */ new Map();
	for (const [key, value] of merged) if (key === "registry") registry = tryNormalize(value) ?? registry;
	else if (/^@[^:]+:registry$/.test(key)) {
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
	return {
		registry,
		scopes,
		auth: [...auth.values()]
	};
}
function withSlash(prefix) {
	return prefix.endsWith("/") ? prefix : `${prefix}/`;
}
function tryNormalize(url) {
	try {
		return normalizeRegistry(url);
	} catch {
		return;
	}
}
/**
* Loads npm configuration from the user's `.npmrc` (`$NPM_CONFIG_USERCONFIG` or
* `~/.npmrc`), then the project's `.npmrc` in `cwd`, then `npm_config_registry`.
* Missing files are ignored.
*/
async function loadNpmConfig(opts = {}) {
	const env = opts.env ?? process.env;
	const cwd = opts.cwd ?? process.cwd();
	const layers = [await readNpmrc(envValue(env, "npm_config_userconfig") ?? join(opts.home ?? homedir(), ".npmrc"), env), await readNpmrc(join(cwd, ".npmrc"), env)];
	const envRegistry = envValue(env, "npm_config_registry");
	if (envRegistry) layers.push(/* @__PURE__ */ new Map([["registry", envRegistry]]));
	return npmConfigFrom(...layers);
}
function envValue(env, lowerName) {
	return env[lowerName] ?? env[lowerName.toUpperCase()];
}
async function readNpmrc(path, env) {
	try {
		return parseNpmrc(await readFile(path, "utf8"), env);
	} catch {
		return /* @__PURE__ */ new Map();
	}
}
/** Picks the registry for a package name, honouring `@scope:registry`. */
function registryFor(config, name) {
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
function authHeaderFor(config, url) {
	let dart;
	try {
		const u = new URL(url);
		if (u.protocol !== "https:" && u.protocol !== "http:") return void 0;
		dart = `//${u.host}${u.pathname}`;
	} catch {
		return;
	}
	let best;
	for (const entry of config.auth) if (dart.startsWith(entry.prefix) && (!best || entry.prefix.length > best.prefix.length)) best = entry;
	if (best?.token) return `Bearer ${best.token.reveal()}`;
	if (best?.basic) return `Basic ${best.basic.reveal()}`;
}
var NPM_REGISTRY;
var init_npmrc = __esmMin((() => {
	init_secret();
	NPM_REGISTRY = "https://registry.npmjs.org/";
}));
// ../packages/core/src/registry/types.ts
function isRecord$2(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Keeps only string values of a record, so lookups never hit odd types. */
function stringRecord(value) {
	const out = {};
	if (!isRecord$2(value)) return out;
	for (const [k, v] of Object.entries(value)) if (typeof v === "string") out[k] = v;
	return out;
}
/**
* Validates the minimum structure of a packument. Versions without a string
* `dist.tarball` are dropped. Throws `INVALID_RESPONSE` when the document is not a
* packument at all.
*/
function toPackument(doc, expectedName) {
	if (!isRecord$2(doc) || !isRecord$2(doc["versions"])) throw new DepwardError("INVALID_RESPONSE", `registry document for ${expectedName} is not a packument`);
	if (doc["name"] !== expectedName) throw new DepwardError("INVALID_RESPONSE", `registry returned a packument for a different package than ${expectedName}`);
	const versions = {};
	for (const [v, meta] of Object.entries(doc["versions"])) if (isRecord$2(meta) && isRecord$2(meta["dist"]) && typeof meta["dist"]["tarball"] === "string") versions[v] = {
		...meta,
		name: expectedName,
		version: v
	};
	return {
		...doc,
		name: expectedName,
		"dist-tags": stringRecord(doc["dist-tags"]),
		versions,
		time: stringRecord(doc["time"])
	};
}
/** Looks up a version or dist-tag in a packument using own properties only. */
function pickVersion(packument, versionOrTag) {
	const { versions } = packument;
	if (Object.hasOwn(versions, versionOrTag)) return versions[versionOrTag] ?? null;
	const tags = packument["dist-tags"];
	if (Object.hasOwn(tags, versionOrTag)) {
		const target = tags[versionOrTag];
		if (target !== void 0 && Object.hasOwn(versions, target)) return versions[target] ?? null;
	}
	return null;
}
/** Reads `dist.attestations`, resolving its URL against the registry. */
function attestationsOf(meta, registry) {
	const raw = meta.dist.attestations;
	if (!isRecord$2(raw) || typeof raw["url"] !== "string") return null;
	let url;
	try {
		url = new URL(raw["url"], registry).href;
	} catch {
		return null;
	}
	const prov = raw["provenance"];
	const predicateType = isRecord$2(prov) && typeof prov["predicateType"] === "string" ? prov["predicateType"] : null;
	return {
		url,
		provenancePredicateType: predicateType
	};
}
/**
* Throws `INVALID_ARGUMENT` unless `name` looks like an npm package name. This keeps
* names such as `../-/whoami` out of registry URLs. Legacy upper-case names are allowed.
*/
function assertPackageName(name) {
	const base = name.slice(name.indexOf("/") + 1);
	if (name.length > 214 || !NAME_RE.test(name) || base === "." || base === "..") throw new DepwardError("INVALID_ARGUMENT", "invalid package name");
}
/** The packument path segment: `@scope%2fname` for scoped names. */
function packumentPath(name) {
	return name.startsWith("@") ? name.replace("/", "%2f") : name;
}
var NAME_RE;
var init_types$2 = __esmMin((() => {
	init_errors();
	NAME_RE = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9_.~-][\w.~-]*$/i;
}));
// ../packages/core/src/registry/client.ts
/** Creates a {@link RegistryClient}. Configuration is resolved lazily on first use. */
function createRegistryClient(opts = {}) {
	const doFetch = opts.fetch ?? globalThis.fetch;
	const cache = opts.cache === void 0 ? createDiskCache() : opts.cache;
	const timeoutMs = opts.timeoutMs ?? 8e3;
	const now = opts.now ?? Date.now;
	const offline = opts.offline ?? (opts.env ?? process.env)["DEPWARD_OFFLINE"] === "1";
	const ttlPackument = opts.ttl?.packument ?? 10 * MINUTE;
	const ttlDownloads = opts.ttl?.downloads ?? 1440 * MINUTE;
	const packumentBytes = opts.limits?.packumentBytes ?? 134217728;
	const tarballBytes = opts.limits?.tarballBytes ?? 52428800;
	const downloadsApi = normalizeRegistry(opts.downloadsApi ?? "https://api.npmjs.org/");
	let configPromise;
	const config = () => configPromise ??= resolveConfig(opts);
	const memo = /* @__PURE__ */ new Map();
	async function cacheGet(ns, key) {
		try {
			return await cache?.get(ns, key) ?? null;
		} catch {
			return null;
		}
	}
	async function cacheSet(ns, key, entry) {
		try {
			await cache?.set(ns, key, entry);
		} catch {}
	}
	/** GET JSON with TTL and ETag revalidation. Returns `null` on 404. */
	async function cachedGet(ns, key, url, ttl, maxBytes, cfg) {
		const cached = await cacheGet(ns, key);
		if (offline) {
			if (cached) return cached.body;
			throw new DepwardError("OFFLINE", `offline mode: ${ns} for ${key} is not cached`);
		}
		if (cached && now() - cached.storedAt < ttl) return cached.body;
		const headers = {
			accept: "application/json",
			"user-agent": USER_AGENT
		};
		if (cached?.etag) headers["if-none-match"] = cached.etag;
		const res = await httpGet(url, {
			fetch: doFetch,
			headers,
			timeoutMs,
			maxBytes,
			...cfg ? { authFor: (u) => authHeaderFor(cfg, u) } : {}
		});
		if (res.status === 304 && cached) {
			await cacheSet(ns, key, {
				...cached,
				storedAt: now()
			});
			return cached.body;
		}
		if (res.status === 404) return null;
		if (res.status !== 200) throw new DepwardError("NETWORK", `registry responded with HTTP ${res.status} for ${ns} ${key}`);
		const entry = {
			body: res.body,
			storedAt: now()
		};
		const etag = res.headers.get("etag");
		if (etag) entry.etag = etag;
		await cacheSet(ns, key, entry);
		return res.body;
	}
	async function loadPackument(name) {
		const cfg = await config();
		const registry = registryFor(cfg, name);
		const body = await cachedGet("packument", `${registry} ${name}`, registry + packumentPath(name), ttlPackument, packumentBytes, cfg);
		return body === null ? null : toPackument(parseJson(body, `packument for ${name}`), name);
	}
	function packument(name) {
		try {
			assertPackageName(name);
		} catch (err) {
			return Promise.reject(err);
		}
		const hit = memo.get(name);
		if (hit && now() - hit.at < ttlPackument) return hit.value;
		const value = loadPackument(name);
		memo.delete(name);
		memo.set(name, {
			at: now(),
			value
		});
		if (memo.size > MEMO_MAX) memo.delete(memo.keys().next().value);
		const forget = () => {
			if (memo.get(name)?.value === value) memo.delete(name);
		};
		value.then((doc) => doc === null && forget(), forget);
		return value;
	}
	return {
		packument,
		async versionMeta(name, version) {
			const doc = await packument(name);
			return doc ? pickVersion(doc, version) : null;
		},
		async attestations(name, version) {
			const doc = await packument(name);
			const meta = doc ? pickVersion(doc, version) : null;
			return meta ? attestationsOf(meta, registryFor(await config(), name)) : null;
		},
		async weeklyDownloads(name) {
			assertPackageName(name);
			const registry = registryFor(await config(), name);
			if (!PUBLIC_REGISTRY_HOSTS.has(new URL(registry).hostname)) return null;
			const body = await cachedGet("downloads", name, `${downloadsApi}downloads/point/last-week/${name}`, ttlDownloads, 65536, null);
			if (body === null) return null;
			const doc = parseJson(body, `download counts for ${name}`);
			return typeof doc.downloads === "number" && Number.isFinite(doc.downloads) ? doc.downloads : null;
		},
		async tarball(meta) {
			const cfg = await config();
			const { dist } = meta;
			const sri = dist.integrity ? strongestHash(dist.integrity) : null;
			const key = sri ? `${sri.algorithm}-${sri.digest}` : null;
			if (key) {
				const cached = await cacheGet("tarball", key);
				if (cached) try {
					verifyIntegrity(cached.body, dist);
					return cached.body;
				} catch {}
			}
			if (offline) throw new DepwardError("OFFLINE", `offline mode: the tarball of ${meta.name}@${meta.version} is not cached`);
			const res = await httpGet(dist.tarball, {
				fetch: doFetch,
				headers: { "user-agent": USER_AGENT },
				timeoutMs,
				maxBytes: tarballBytes,
				authFor: (u) => authHeaderFor(cfg, u)
			});
			if (res.status !== 200) throw new DepwardError("NETWORK", `tarball download for ${meta.name}@${meta.version} returned HTTP ${res.status}`);
			verifyIntegrity(res.body, dist);
			if (key) await cacheSet("tarball", key, {
				body: res.body,
				storedAt: now()
			});
			return res.body;
		}
	};
}
async function resolveConfig(opts) {
	const base = opts.npmConfig ?? await loadNpmConfig({
		...opts.cwd === void 0 ? {} : { cwd: opts.cwd },
		...opts.env === void 0 ? {} : { env: opts.env }
	});
	const cfg = {
		registry: base.registry,
		scopes: { ...base.scopes },
		auth: [...base.auth]
	};
	if (opts.registry !== void 0) try {
		cfg.registry = normalizeRegistry(opts.registry);
	} catch (cause) {
		throw new DepwardError("INVALID_ARGUMENT", "invalid registry URL", { cause });
	}
	if (opts.token !== void 0) {
		const prefix = nerfDart(cfg.registry);
		cfg.auth = [...cfg.auth.filter((a) => a.prefix !== prefix), {
			prefix,
			token: new Secret(opts.token)
		}];
	}
	return cfg;
}
var MINUTE, USER_AGENT, PUBLIC_REGISTRY_HOSTS, MEMO_MAX;
var init_client = __esmMin((() => {
	init_cache();
	init_errors();
	init_integrity();
	init_secret();
	init_http();
	init_npmrc();
	init_types$2();
	MINUTE = 6e4;
	USER_AGENT = "depward (+https://github.com/lavitsamson/depward)";
	PUBLIC_REGISTRY_HOSTS = /* @__PURE__ */ new Set(["registry.npmjs.org", "registry.npmjs.com"]);
	MEMO_MAX = 100;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/identity.js
var require_identity = /* @__PURE__ */ __commonJSMin(((exports) => {
	const ALIAS = Symbol.for("yaml.alias");
	const DOC = Symbol.for("yaml.document");
	const MAP = Symbol.for("yaml.map");
	const PAIR = Symbol.for("yaml.pair");
	const SCALAR = Symbol.for("yaml.scalar");
	const SEQ = Symbol.for("yaml.seq");
	const NODE_TYPE = Symbol.for("yaml.node.type");
	const isAlias = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === ALIAS;
	const isDocument = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === DOC;
	const isMap = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === MAP;
	const isPair = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === PAIR;
	const isScalar = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === SCALAR;
	const isSeq = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === SEQ;
	function isCollection(node) {
		if (node && typeof node === "object") switch (node[NODE_TYPE]) {
			case MAP:
			case SEQ: return true;
		}
		return false;
	}
	function isNode(node) {
		if (node && typeof node === "object") switch (node[NODE_TYPE]) {
			case ALIAS:
			case MAP:
			case SCALAR:
			case SEQ: return true;
		}
		return false;
	}
	const hasAnchor = (node) => (isScalar(node) || isCollection(node)) && !!node.anchor;
	exports.ALIAS = ALIAS;
	exports.DOC = DOC;
	exports.MAP = MAP;
	exports.NODE_TYPE = NODE_TYPE;
	exports.PAIR = PAIR;
	exports.SCALAR = SCALAR;
	exports.SEQ = SEQ;
	exports.hasAnchor = hasAnchor;
	exports.isAlias = isAlias;
	exports.isCollection = isCollection;
	exports.isDocument = isDocument;
	exports.isMap = isMap;
	exports.isNode = isNode;
	exports.isPair = isPair;
	exports.isScalar = isScalar;
	exports.isSeq = isSeq;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/visit.js
var require_visit = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	const BREAK = Symbol("break visit");
	const SKIP = Symbol("skip children");
	const REMOVE = Symbol("remove node");
	/**
	* Apply a visitor to an AST node or document.
	*
	* Walks through the tree (depth-first) starting from `node`, calling a
	* `visitor` function with three arguments:
	*   - `key`: For sequence values and map `Pair`, the node's index in the
	*     collection. Within a `Pair`, `'key'` or `'value'`, correspondingly.
	*     `null` for the root node.
	*   - `node`: The current node.
	*   - `path`: The ancestry of the current node.
	*
	* The return value of the visitor may be used to control the traversal:
	*   - `undefined` (default): Do nothing and continue
	*   - `visit.SKIP`: Do not visit the children of this node, continue with next
	*     sibling
	*   - `visit.BREAK`: Terminate traversal completely
	*   - `visit.REMOVE`: Remove the current node, then continue with the next one
	*   - `Node`: Replace the current node, then continue by visiting it
	*   - `number`: While iterating the items of a sequence or map, set the index
	*     of the next step. This is useful especially if the index of the current
	*     node has changed.
	*
	* If `visitor` is a single function, it will be called with all values
	* encountered in the tree, including e.g. `null` values. Alternatively,
	* separate visitor functions may be defined for each `Map`, `Pair`, `Seq`,
	* `Alias` and `Scalar` node. To define the same visitor function for more than
	* one node type, use the `Collection` (map and seq), `Value` (map, seq & scalar)
	* and `Node` (alias, map, seq & scalar) targets. Of all these, only the most
	* specific defined one will be used for each node.
	*/
	function visit(node, visitor) {
		const visitor_ = initVisitor(visitor);
		if (identity.isDocument(node)) {
			if (visit_(null, node.contents, visitor_, Object.freeze([node])) === REMOVE) node.contents = null;
		} else visit_(null, node, visitor_, Object.freeze([]));
	}
	/** Terminate visit traversal completely */
	visit.BREAK = BREAK;
	/** Do not visit the children of the current node */
	visit.SKIP = SKIP;
	/** Remove the current node */
	visit.REMOVE = REMOVE;
	function visit_(key, node, visitor, path) {
		const ctrl = callVisitor(key, node, visitor, path);
		if (identity.isNode(ctrl) || identity.isPair(ctrl)) {
			replaceNode(key, path, ctrl);
			return visit_(key, ctrl, visitor, path);
		}
		if (typeof ctrl !== "symbol") {
			if (identity.isCollection(node)) {
				path = Object.freeze(path.concat(node));
				for (let i = 0; i < node.items.length; ++i) {
					const ci = visit_(i, node.items[i], visitor, path);
					if (typeof ci === "number") i = ci - 1;
					else if (ci === BREAK) return BREAK;
					else if (ci === REMOVE) {
						node.items.splice(i, 1);
						i -= 1;
					}
				}
			} else if (identity.isPair(node)) {
				path = Object.freeze(path.concat(node));
				const ck = visit_("key", node.key, visitor, path);
				if (ck === BREAK) return BREAK;
				else if (ck === REMOVE) node.key = null;
				const cv = visit_("value", node.value, visitor, path);
				if (cv === BREAK) return BREAK;
				else if (cv === REMOVE) node.value = null;
			}
		}
		return ctrl;
	}
	/**
	* Apply an async visitor to an AST node or document.
	*
	* Walks through the tree (depth-first) starting from `node`, calling a
	* `visitor` function with three arguments:
	*   - `key`: For sequence values and map `Pair`, the node's index in the
	*     collection. Within a `Pair`, `'key'` or `'value'`, correspondingly.
	*     `null` for the root node.
	*   - `node`: The current node.
	*   - `path`: The ancestry of the current node.
	*
	* The return value of the visitor may be used to control the traversal:
	*   - `Promise`: Must resolve to one of the following values
	*   - `undefined` (default): Do nothing and continue
	*   - `visit.SKIP`: Do not visit the children of this node, continue with next
	*     sibling
	*   - `visit.BREAK`: Terminate traversal completely
	*   - `visit.REMOVE`: Remove the current node, then continue with the next one
	*   - `Node`: Replace the current node, then continue by visiting it
	*   - `number`: While iterating the items of a sequence or map, set the index
	*     of the next step. This is useful especially if the index of the current
	*     node has changed.
	*
	* If `visitor` is a single function, it will be called with all values
	* encountered in the tree, including e.g. `null` values. Alternatively,
	* separate visitor functions may be defined for each `Map`, `Pair`, `Seq`,
	* `Alias` and `Scalar` node. To define the same visitor function for more than
	* one node type, use the `Collection` (map and seq), `Value` (map, seq & scalar)
	* and `Node` (alias, map, seq & scalar) targets. Of all these, only the most
	* specific defined one will be used for each node.
	*/
	async function visitAsync(node, visitor) {
		const visitor_ = initVisitor(visitor);
		if (identity.isDocument(node)) {
			if (await visitAsync_(null, node.contents, visitor_, Object.freeze([node])) === REMOVE) node.contents = null;
		} else await visitAsync_(null, node, visitor_, Object.freeze([]));
	}
	/** Terminate visit traversal completely */
	visitAsync.BREAK = BREAK;
	/** Do not visit the children of the current node */
	visitAsync.SKIP = SKIP;
	/** Remove the current node */
	visitAsync.REMOVE = REMOVE;
	async function visitAsync_(key, node, visitor, path) {
		const ctrl = await callVisitor(key, node, visitor, path);
		if (identity.isNode(ctrl) || identity.isPair(ctrl)) {
			replaceNode(key, path, ctrl);
			return visitAsync_(key, ctrl, visitor, path);
		}
		if (typeof ctrl !== "symbol") {
			if (identity.isCollection(node)) {
				path = Object.freeze(path.concat(node));
				for (let i = 0; i < node.items.length; ++i) {
					const ci = await visitAsync_(i, node.items[i], visitor, path);
					if (typeof ci === "number") i = ci - 1;
					else if (ci === BREAK) return BREAK;
					else if (ci === REMOVE) {
						node.items.splice(i, 1);
						i -= 1;
					}
				}
			} else if (identity.isPair(node)) {
				path = Object.freeze(path.concat(node));
				const ck = await visitAsync_("key", node.key, visitor, path);
				if (ck === BREAK) return BREAK;
				else if (ck === REMOVE) node.key = null;
				const cv = await visitAsync_("value", node.value, visitor, path);
				if (cv === BREAK) return BREAK;
				else if (cv === REMOVE) node.value = null;
			}
		}
		return ctrl;
	}
	function initVisitor(visitor) {
		if (typeof visitor === "object" && (visitor.Collection || visitor.Node || visitor.Value)) return Object.assign({
			Alias: visitor.Node,
			Map: visitor.Node,
			Scalar: visitor.Node,
			Seq: visitor.Node
		}, visitor.Value && {
			Map: visitor.Value,
			Scalar: visitor.Value,
			Seq: visitor.Value
		}, visitor.Collection && {
			Map: visitor.Collection,
			Seq: visitor.Collection
		}, visitor);
		return visitor;
	}
	function callVisitor(key, node, visitor, path) {
		if (typeof visitor === "function") return visitor(key, node, path);
		if (identity.isMap(node)) return visitor.Map?.(key, node, path);
		if (identity.isSeq(node)) return visitor.Seq?.(key, node, path);
		if (identity.isPair(node)) return visitor.Pair?.(key, node, path);
		if (identity.isScalar(node)) return visitor.Scalar?.(key, node, path);
		if (identity.isAlias(node)) return visitor.Alias?.(key, node, path);
	}
	function replaceNode(key, path, node) {
		const parent = path[path.length - 1];
		if (identity.isCollection(parent)) parent.items[key] = node;
		else if (identity.isPair(parent)) {
			if (key === "key") parent.key = node;
			else parent.value = node;
		} else if (identity.isDocument(parent)) parent.contents = node;
		else {
			const pt = identity.isAlias(parent) ? "alias" : "scalar";
			throw new Error(`Cannot replace node with ${pt} parent`);
		}
	}
	exports.visit = visit;
	exports.visitAsync = visitAsync;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/doc/directives.js
var require_directives = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var visit = require_visit();
	const escapeChars = {
		"!": "%21",
		",": "%2C",
		"[": "%5B",
		"]": "%5D",
		"{": "%7B",
		"}": "%7D"
	};
	const escapeTagName = (tn) => tn.replace(/[!,[\]{}]/g, (ch) => escapeChars[ch]);
	var Directives = class Directives {
		constructor(yaml, tags) {
			/**
			* The directives-end/doc-start marker `---`. If `null`, a marker may still be
			* included in the document's stringified representation.
			*/
			this.docStart = null;
			/** The doc-end marker `...`.  */
			this.docEnd = false;
			this.yaml = Object.assign({}, Directives.defaultYaml, yaml);
			this.tags = Object.assign({}, Directives.defaultTags, tags);
		}
		clone() {
			const copy = new Directives(this.yaml, this.tags);
			copy.docStart = this.docStart;
			return copy;
		}
		/**
		* During parsing, get a Directives instance for the current document and
		* update the stream state according to the current version's spec.
		*/
		atDocument() {
			const res = new Directives(this.yaml, this.tags);
			switch (this.yaml.version) {
				case "1.1":
					this.atNextDocument = true;
					break;
				case "1.2":
					this.atNextDocument = false;
					this.yaml = {
						explicit: Directives.defaultYaml.explicit,
						version: "1.2"
					};
					this.tags = Object.assign({}, Directives.defaultTags);
			}
			return res;
		}
		/**
		* @param onError - May be called even if the action was successful
		* @returns `true` on success
		*/
		add(line, onError) {
			if (this.atNextDocument) {
				this.yaml = {
					explicit: Directives.defaultYaml.explicit,
					version: "1.1"
				};
				this.tags = Object.assign({}, Directives.defaultTags);
				this.atNextDocument = false;
			}
			const parts = line.trim().split(/[ \t]+/);
			const name = parts.shift();
			switch (name) {
				case "%TAG": {
					if (parts.length !== 2) {
						onError(0, "%TAG directive should contain exactly two parts");
						if (parts.length < 2) return false;
					}
					const [handle, prefix] = parts;
					this.tags[handle] = prefix;
					return true;
				}
				case "%YAML": {
					this.yaml.explicit = true;
					if (parts.length !== 1) {
						onError(0, "%YAML directive should contain exactly one part");
						return false;
					}
					const [version] = parts;
					if (version === "1.1" || version === "1.2") {
						this.yaml.version = version;
						return true;
					} else {
						const isValid = /^\d+\.\d+$/.test(version);
						onError(6, `Unsupported YAML version ${version}`, isValid);
						return false;
					}
				}
				default:
					onError(0, `Unknown directive ${name}`, true);
					return false;
			}
		}
		/**
		* Resolves a tag, matching handles to those defined in %TAG directives.
		*
		* @returns Resolved tag, which may also be the non-specific tag `'!'` or a
		*   `'!local'` tag, or `null` if unresolvable.
		*/
		tagName(source, onError) {
			if (source === "!") return "!";
			if (source[0] !== "!") {
				onError(`Not a valid tag: ${source}`);
				return null;
			}
			if (source[1] === "<") {
				const verbatim = source.slice(2, -1);
				if (verbatim === "!" || verbatim === "!!") {
					onError(`Verbatim tags aren't resolved, so ${source} is invalid.`);
					return null;
				}
				if (source[source.length - 1] !== ">") onError("Verbatim tags must end with a >");
				return verbatim;
			}
			const [, handle, suffix] = source.match(/^(.*!)([^!]*)$/s);
			if (!suffix) onError(`The ${source} tag has no suffix`);
			const prefix = this.tags[handle];
			if (prefix) try {
				return prefix + decodeURIComponent(suffix);
			} catch (error) {
				onError(String(error));
				return null;
			}
			if (handle === "!") return source;
			onError(`Could not resolve tag: ${source}`);
			return null;
		}
		/**
		* Given a fully resolved tag, returns its printable string form,
		* taking into account current tag prefixes and defaults.
		*/
		tagString(tag) {
			for (const [handle, prefix] of Object.entries(this.tags)) if (tag.startsWith(prefix)) return handle + escapeTagName(tag.substring(prefix.length));
			return tag[0] === "!" ? tag : `!<${tag}>`;
		}
		toString(doc) {
			const lines = this.yaml.explicit ? [`%YAML ${this.yaml.version || "1.2"}`] : [];
			const tagEntries = Object.entries(this.tags);
			let tagNames;
			if (doc && tagEntries.length > 0 && identity.isNode(doc.contents)) {
				const tags = {};
				visit.visit(doc.contents, (_key, node) => {
					if (identity.isNode(node) && node.tag) tags[node.tag] = true;
				});
				tagNames = Object.keys(tags);
			} else tagNames = [];
			for (const [handle, prefix] of tagEntries) {
				if (handle === "!!" && prefix === "tag:yaml.org,2002:") continue;
				if (!doc || tagNames.some((tn) => tn.startsWith(prefix))) lines.push(`%TAG ${handle} ${prefix}`);
			}
			return lines.join("\n");
		}
	};
	Directives.defaultYaml = {
		explicit: false,
		version: "1.2"
	};
	Directives.defaultTags = { "!!": "tag:yaml.org,2002:" };
	exports.Directives = Directives;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/doc/anchors.js
var require_anchors = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var visit = require_visit();
	/**
	* Verify that the input string is a valid anchor.
	*
	* Will throw on errors.
	*/
	function anchorIsValid(anchor) {
		if (/[\x00-\x19\s,[\]{}]/.test(anchor)) {
			const msg = `Anchor must not contain whitespace or control characters: ${JSON.stringify(anchor)}`;
			throw new Error(msg);
		}
		return true;
	}
	function anchorNames(root) {
		const anchors = /* @__PURE__ */ new Set();
		visit.visit(root, { Value(_key, node) {
			if (node.anchor) anchors.add(node.anchor);
		} });
		return anchors;
	}
	/** Find a new anchor name with the given `prefix` and a one-indexed suffix. */
	function findNewAnchor(prefix, exclude) {
		for (let i = 1;; ++i) {
			const name = `${prefix}${i}`;
			if (!exclude.has(name)) return name;
		}
	}
	function createNodeAnchors(doc, prefix) {
		const aliasObjects = [];
		const sourceObjects = /* @__PURE__ */ new Map();
		let prevAnchors = null;
		return {
			onAnchor: (source) => {
				aliasObjects.push(source);
				prevAnchors ?? (prevAnchors = anchorNames(doc));
				const anchor = findNewAnchor(prefix, prevAnchors);
				prevAnchors.add(anchor);
				return anchor;
			},
			/**
			* With circular references, the source node is only resolved after all
			* of its child nodes are. This is why anchors are set only after all of
			* the nodes have been created.
			*/
			setAnchors: () => {
				for (const source of aliasObjects) {
					const ref = sourceObjects.get(source);
					if (typeof ref === "object" && ref.anchor && (identity.isScalar(ref.node) || identity.isCollection(ref.node))) ref.node.anchor = ref.anchor;
					else {
						const error = /* @__PURE__ */ new Error("Failed to resolve repeated object (this should not happen)");
						error.source = source;
						throw error;
					}
				}
			},
			sourceObjects
		};
	}
	exports.anchorIsValid = anchorIsValid;
	exports.anchorNames = anchorNames;
	exports.createNodeAnchors = createNodeAnchors;
	exports.findNewAnchor = findNewAnchor;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/doc/applyReviver.js
var require_applyReviver = /* @__PURE__ */ __commonJSMin(((exports) => {
	/**
	* Applies the JSON.parse reviver algorithm as defined in the ECMA-262 spec,
	* in section 24.5.1.1 "Runtime Semantics: InternalizeJSONProperty" of the
	* 2021 edition: https://tc39.es/ecma262/#sec-json.parse
	*
	* Includes extensions for handling Map and Set objects.
	*/
	function applyReviver(reviver, obj, key, val) {
		if (val && typeof val === "object") {
			if (Array.isArray(val)) for (let i = 0, len = val.length; i < len; ++i) {
				const v0 = val[i];
				const v1 = applyReviver(reviver, val, String(i), v0);
				if (v1 === void 0) delete val[i];
				else if (v1 !== v0) val[i] = v1;
			}
			else if (val instanceof Map) for (const k of Array.from(val.keys())) {
				const v0 = val.get(k);
				const v1 = applyReviver(reviver, val, k, v0);
				if (v1 === void 0) val.delete(k);
				else if (v1 !== v0) val.set(k, v1);
			}
			else if (val instanceof Set) for (const v0 of Array.from(val)) {
				const v1 = applyReviver(reviver, val, v0, v0);
				if (v1 === void 0) val.delete(v0);
				else if (v1 !== v0) {
					val.delete(v0);
					val.add(v1);
				}
			}
			else for (const [k, v0] of Object.entries(val)) {
				const v1 = applyReviver(reviver, val, k, v0);
				if (v1 === void 0) delete val[k];
				else if (v1 !== v0) val[k] = v1;
			}
		}
		return reviver.call(obj, key, val);
	}
	exports.applyReviver = applyReviver;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/toJS.js
var require_toJS = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	/**
	* Recursively convert any node or its contents to native JavaScript
	*
	* @param value - The input value
	* @param arg - If `value` defines a `toJSON()` method, use this
	*   as its first argument
	* @param ctx - Conversion context, originally set in Document#toJS(). If
	*   `{ keep: true }` is not set, output should be suitable for JSON
	*   stringification.
	*/
	function toJS(value, arg, ctx) {
		if (Array.isArray(value)) return value.map((v, i) => toJS(v, String(i), ctx));
		if (value && typeof value.toJSON === "function") {
			if (!ctx || !identity.hasAnchor(value)) return value.toJSON(arg, ctx);
			const data = {
				aliasCount: 0,
				count: 1,
				res: void 0
			};
			ctx.anchors.set(value, data);
			ctx.onCreate = (res) => {
				data.res = res;
				delete ctx.onCreate;
			};
			const res = value.toJSON(arg, ctx);
			if (ctx.onCreate) ctx.onCreate(res);
			return res;
		}
		if (typeof value === "bigint" && !ctx?.keep) return Number(value);
		return value;
	}
	exports.toJS = toJS;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/Node.js
var require_Node = /* @__PURE__ */ __commonJSMin(((exports) => {
	var applyReviver = require_applyReviver();
	var identity = require_identity();
	var toJS = require_toJS();
	var NodeBase = class {
		constructor(type) {
			Object.defineProperty(this, identity.NODE_TYPE, { value: type });
		}
		/** Create a copy of this node.  */
		clone() {
			const copy = Object.create(Object.getPrototypeOf(this), Object.getOwnPropertyDescriptors(this));
			if (this.range) copy.range = this.range.slice();
			return copy;
		}
		/** A plain JavaScript representation of this node. */
		toJS(doc, { mapAsMap, maxAliasCount, onAnchor, reviver } = {}) {
			if (!identity.isDocument(doc)) throw new TypeError("A document argument is required");
			const ctx = {
				anchors: /* @__PURE__ */ new Map(),
				doc,
				keep: true,
				mapAsMap: mapAsMap === true,
				mapKeyWarned: false,
				maxAliasCount: typeof maxAliasCount === "number" ? maxAliasCount : 100
			};
			const res = toJS.toJS(this, "", ctx);
			if (typeof onAnchor === "function") for (const { count, res } of ctx.anchors.values()) onAnchor(res, count);
			return typeof reviver === "function" ? applyReviver.applyReviver(reviver, { "": res }, "", res) : res;
		}
	};
	exports.NodeBase = NodeBase;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/Alias.js
var require_Alias = /* @__PURE__ */ __commonJSMin(((exports) => {
	var anchors = require_anchors();
	var visit = require_visit();
	var identity = require_identity();
	var Node = require_Node();
	var toJS = require_toJS();
	var Alias = class extends Node.NodeBase {
		constructor(source) {
			super(identity.ALIAS);
			this.source = source;
			Object.defineProperty(this, "tag", { set() {
				throw new Error("Alias nodes cannot have tags");
			} });
		}
		/**
		* Resolve the value of this alias within `doc`, finding the last
		* instance of the `source` anchor before this node.
		*/
		resolve(doc, ctx) {
			if (ctx?.maxAliasCount === 0) throw new ReferenceError("Alias resolution is disabled");
			let nodes;
			if (ctx?.aliasResolveCache) nodes = ctx.aliasResolveCache;
			else {
				nodes = [];
				visit.visit(doc, { Node: (_key, node) => {
					if (identity.isAlias(node) || identity.hasAnchor(node)) nodes.push(node);
				} });
				if (ctx) ctx.aliasResolveCache = nodes;
			}
			let found = void 0;
			for (const node of nodes) {
				if (node === this) break;
				if (node.anchor === this.source) found = node;
			}
			if (found && ctx) {
				const { anchors, doc, maxAliasCount } = ctx;
				let data = anchors.get(found);
				if (!data) {
					toJS.toJS(found, null, ctx);
					data = anchors.get(found);
				}
				/* istanbul ignore if */
				if (data?.res === void 0) throw new ReferenceError("This should not happen: Alias anchor was not resolved?");
				if (maxAliasCount >= 0) {
					data.count += 1;
					if (data.aliasCount === 0) data.aliasCount = getAliasCount(doc, found, anchors);
					if (data.count * data.aliasCount > maxAliasCount) throw new ReferenceError("Excessive alias count indicates a resource exhaustion attack");
				}
			}
			return found;
		}
		toJSON(_arg, ctx) {
			if (!ctx) return { source: this.source };
			const source = this.resolve(ctx.doc, ctx);
			if (!source) {
				const msg = `Unresolved alias (the anchor must be set before the alias): ${this.source}`;
				throw new ReferenceError(msg);
			}
			return ctx.anchors.get(source).res;
		}
		toString(ctx, _onComment, _onChompKeep) {
			const src = `*${this.source}`;
			if (ctx) {
				anchors.anchorIsValid(this.source);
				if (ctx.options.verifyAliasOrder && !ctx.anchors.has(this.source)) {
					const msg = `Unresolved alias (the anchor must be set before the alias): ${this.source}`;
					throw new Error(msg);
				}
				if (ctx.implicitKey) return `${src} `;
			}
			return src;
		}
	};
	function getAliasCount(doc, node, anchors) {
		if (identity.isAlias(node)) {
			const source = node.resolve(doc);
			const anchor = anchors && source && anchors.get(source);
			return anchor ? anchor.count * anchor.aliasCount : 0;
		} else if (identity.isCollection(node)) {
			let count = 0;
			for (const item of node.items) {
				const c = getAliasCount(doc, item, anchors);
				if (c > count) count = c;
			}
			return count;
		} else if (identity.isPair(node)) {
			const kc = getAliasCount(doc, node.key, anchors);
			const vc = getAliasCount(doc, node.value, anchors);
			return Math.max(kc, vc);
		}
		return 1;
	}
	exports.Alias = Alias;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/Scalar.js
var require_Scalar = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Node = require_Node();
	var toJS = require_toJS();
	const isScalarValue = (value) => !value || typeof value !== "function" && typeof value !== "object";
	var Scalar = class extends Node.NodeBase {
		constructor(value) {
			super(identity.SCALAR);
			this.value = value;
		}
		toJSON(arg, ctx) {
			return ctx?.keep ? this.value : toJS.toJS(this.value, arg, ctx);
		}
		toString() {
			return String(this.value);
		}
	};
	Scalar.BLOCK_FOLDED = "BLOCK_FOLDED";
	Scalar.BLOCK_LITERAL = "BLOCK_LITERAL";
	Scalar.PLAIN = "PLAIN";
	Scalar.QUOTE_DOUBLE = "QUOTE_DOUBLE";
	Scalar.QUOTE_SINGLE = "QUOTE_SINGLE";
	exports.Scalar = Scalar;
	exports.isScalarValue = isScalarValue;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/doc/createNode.js
var require_createNode = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Alias = require_Alias();
	var identity = require_identity();
	var Scalar = require_Scalar();
	const defaultTagPrefix = "tag:yaml.org,2002:";
	function findTagObject(value, tagName, tags) {
		if (tagName) {
			const match = tags.filter((t) => t.tag === tagName);
			const tagObj = match.find((t) => !t.format) ?? match[0];
			if (!tagObj) throw new Error(`Tag ${tagName} not found`);
			return tagObj;
		}
		return tags.find((t) => t.identify?.(value) && !t.format);
	}
	function createNode(value, tagName, ctx) {
		if (identity.isDocument(value)) value = value.contents;
		if (identity.isNode(value)) return value;
		if (identity.isPair(value)) {
			const map = ctx.schema[identity.MAP].createNode?.(ctx.schema, null, ctx);
			map.items.push(value);
			return map;
		}
		if (value instanceof String || value instanceof Number || value instanceof Boolean || typeof BigInt !== "undefined" && value instanceof BigInt) value = value.valueOf();
		const { aliasDuplicateObjects, onAnchor, onTagObj, schema, sourceObjects } = ctx;
		let ref = void 0;
		if (aliasDuplicateObjects && value && typeof value === "object") {
			ref = sourceObjects.get(value);
			if (ref) {
				ref.anchor ?? (ref.anchor = onAnchor(value));
				return new Alias.Alias(ref.anchor);
			} else {
				ref = {
					anchor: null,
					node: null
				};
				sourceObjects.set(value, ref);
			}
		}
		if (tagName?.startsWith("!!")) tagName = defaultTagPrefix + tagName.slice(2);
		let tagObj = findTagObject(value, tagName, schema.tags);
		if (!tagObj) {
			if (value && typeof value.toJSON === "function") value = value.toJSON();
			if (!value || typeof value !== "object") {
				const node = new Scalar.Scalar(value);
				if (ref) ref.node = node;
				return node;
			}
			tagObj = value instanceof Map ? schema[identity.MAP] : Symbol.iterator in Object(value) ? schema[identity.SEQ] : schema[identity.MAP];
		}
		if (onTagObj) {
			onTagObj(tagObj);
			delete ctx.onTagObj;
		}
		const node = tagObj?.createNode ? tagObj.createNode(ctx.schema, value, ctx) : typeof tagObj?.nodeClass?.from === "function" ? tagObj.nodeClass.from(ctx.schema, value, ctx) : new Scalar.Scalar(value);
		if (tagName) node.tag = tagName;
		else if (!tagObj.default) node.tag = tagObj.tag;
		if (ref) ref.node = node;
		return node;
	}
	exports.createNode = createNode;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/Collection.js
var require_Collection = /* @__PURE__ */ __commonJSMin(((exports) => {
	var createNode = require_createNode();
	var identity = require_identity();
	var Node = require_Node();
	function collectionFromPath(schema, path, value) {
		let v = value;
		for (let i = path.length - 1; i >= 0; --i) {
			const k = path[i];
			if (typeof k === "number" && Number.isInteger(k) && k >= 0) {
				const a = [];
				a[k] = v;
				v = a;
			} else v = /* @__PURE__ */ new Map([[k, v]]);
		}
		return createNode.createNode(v, void 0, {
			aliasDuplicateObjects: false,
			keepUndefined: false,
			onAnchor: () => {
				throw new Error("This should not happen, please report a bug.");
			},
			schema,
			sourceObjects: /* @__PURE__ */ new Map()
		});
	}
	const isEmptyPath = (path) => path == null || typeof path === "object" && !!path[Symbol.iterator]().next().done;
	var Collection = class extends Node.NodeBase {
		constructor(type, schema) {
			super(type);
			Object.defineProperty(this, "schema", {
				value: schema,
				configurable: true,
				enumerable: false,
				writable: true
			});
		}
		/**
		* Create a copy of this collection.
		*
		* @param schema - If defined, overwrites the original's schema
		*/
		clone(schema) {
			const copy = Object.create(Object.getPrototypeOf(this), Object.getOwnPropertyDescriptors(this));
			if (schema) copy.schema = schema;
			copy.items = copy.items.map((it) => identity.isNode(it) || identity.isPair(it) ? it.clone(schema) : it);
			if (this.range) copy.range = this.range.slice();
			return copy;
		}
		/**
		* Adds a value to the collection. For `!!map` and `!!omap` the value must
		* be a Pair instance or a `{ key, value }` object, which may not have a key
		* that already exists in the map.
		*/
		addIn(path, value) {
			if (isEmptyPath(path)) this.add(value);
			else {
				const [key, ...rest] = path;
				const node = this.get(key, true);
				if (identity.isCollection(node)) node.addIn(rest, value);
				else if (node === void 0 && this.schema) this.set(key, collectionFromPath(this.schema, rest, value));
				else throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
			}
		}
		/**
		* Removes a value from the collection.
		* @returns `true` if the item was found and removed.
		*/
		deleteIn(path) {
			const [key, ...rest] = path;
			if (rest.length === 0) return this.delete(key);
			const node = this.get(key, true);
			if (identity.isCollection(node)) return node.deleteIn(rest);
			else throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
		}
		/**
		* Returns item at `key`, or `undefined` if not found. By default unwraps
		* scalar values from their surrounding node; to disable set `keepScalar` to
		* `true` (collections are always returned intact).
		*/
		getIn(path, keepScalar) {
			const [key, ...rest] = path;
			const node = this.get(key, true);
			if (rest.length === 0) return !keepScalar && identity.isScalar(node) ? node.value : node;
			else return identity.isCollection(node) ? node.getIn(rest, keepScalar) : void 0;
		}
		hasAllNullValues(allowScalar) {
			return this.items.every((node) => {
				if (!identity.isPair(node)) return false;
				const n = node.value;
				return n == null || allowScalar && identity.isScalar(n) && n.value == null && !n.commentBefore && !n.comment && !n.tag;
			});
		}
		/**
		* Checks if the collection includes a value with the key `key`.
		*/
		hasIn(path) {
			const [key, ...rest] = path;
			if (rest.length === 0) return this.has(key);
			const node = this.get(key, true);
			return identity.isCollection(node) ? node.hasIn(rest) : false;
		}
		/**
		* Sets a value in this collection. For `!!set`, `value` needs to be a
		* boolean to add/remove the item from the set.
		*/
		setIn(path, value) {
			const [key, ...rest] = path;
			if (rest.length === 0) this.set(key, value);
			else {
				const node = this.get(key, true);
				if (identity.isCollection(node)) node.setIn(rest, value);
				else if (node === void 0 && this.schema) this.set(key, collectionFromPath(this.schema, rest, value));
				else throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
			}
		}
	};
	exports.Collection = Collection;
	exports.collectionFromPath = collectionFromPath;
	exports.isEmptyPath = isEmptyPath;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringifyComment.js
var require_stringifyComment = /* @__PURE__ */ __commonJSMin(((exports) => {
	/**
	* Stringifies a comment.
	*
	* Empty comment lines are left empty,
	* lines consisting of a single space are replaced by `#`,
	* and all other lines are prefixed with a `#`.
	*/
	const stringifyComment = (str) => str.replace(/^(?!$)(?: $)?/gm, "#");
	function indentComment(comment, indent) {
		if (/^\n+$/.test(comment)) return comment.substring(1);
		return indent ? comment.replace(/^(?! *$)/gm, indent) : comment;
	}
	const lineComment = (str, indent, comment) => str.endsWith("\n") ? indentComment(comment, indent) : comment.includes("\n") ? "\n" + indentComment(comment, indent) : (str.endsWith(" ") ? "" : " ") + comment;
	exports.indentComment = indentComment;
	exports.lineComment = lineComment;
	exports.stringifyComment = stringifyComment;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/foldFlowLines.js
var require_foldFlowLines = /* @__PURE__ */ __commonJSMin(((exports) => {
	const FOLD_FLOW = "flow";
	const FOLD_BLOCK = "block";
	const FOLD_QUOTED = "quoted";
	/**
	* Tries to keep input at up to `lineWidth` characters, splitting only on spaces
	* not followed by newlines or spaces unless `mode` is `'quoted'`. Lines are
	* terminated with `\n` and started with `indent`.
	*/
	function foldFlowLines(text, indent, mode = "flow", { indentAtStart, lineWidth = 80, minContentWidth = 20, onFold, onOverflow } = {}) {
		if (!lineWidth || lineWidth < 0) return text;
		if (lineWidth < minContentWidth) minContentWidth = 0;
		const endStep = Math.max(1 + minContentWidth, 1 + lineWidth - indent.length);
		if (text.length <= endStep) return text;
		const folds = [];
		const escapedFolds = {};
		let end = lineWidth - indent.length;
		if (typeof indentAtStart === "number") {
			if (indentAtStart > lineWidth - Math.max(2, minContentWidth)) folds.push(0);
			else end = lineWidth - indentAtStart;
		}
		let split = void 0;
		let prev = void 0;
		let overflow = false;
		let i = -1;
		let escStart = -1;
		let escEnd = -1;
		if (mode === FOLD_BLOCK) {
			i = consumeMoreIndentedLines(text, i, indent.length);
			if (i !== -1) end = i + endStep;
		}
		for (let ch; ch = text[i += 1];) {
			if (mode === FOLD_QUOTED && ch === "\\") {
				escStart = i;
				switch (text[i + 1]) {
					case "x":
						i += 3;
						break;
					case "u":
						i += 5;
						break;
					case "U":
						i += 9;
						break;
					default: i += 1;
				}
				escEnd = i;
			}
			if (ch === "\n") {
				if (mode === FOLD_BLOCK) i = consumeMoreIndentedLines(text, i, indent.length);
				end = i + indent.length + endStep;
				split = void 0;
			} else {
				if (ch === " " && prev && prev !== " " && prev !== "\n" && prev !== "	") {
					const next = text[i + 1];
					if (next && next !== " " && next !== "\n" && next !== "	") split = i;
				}
				if (i >= end) {
					if (split) {
						folds.push(split);
						end = split + endStep;
						split = void 0;
					} else if (mode === FOLD_QUOTED) {
						while (prev === " " || prev === "	") {
							prev = ch;
							ch = text[i += 1];
							overflow = true;
						}
						const j = i > escEnd + 1 ? i - 2 : escStart - 1;
						if (escapedFolds[j]) return text;
						folds.push(j);
						escapedFolds[j] = true;
						end = j + endStep;
						split = void 0;
					} else overflow = true;
				}
			}
			prev = ch;
		}
		if (overflow && onOverflow) onOverflow();
		if (folds.length === 0) return text;
		if (onFold) onFold();
		let res = text.slice(0, folds[0]);
		for (let i = 0; i < folds.length; ++i) {
			const fold = folds[i];
			const end = folds[i + 1] || text.length;
			if (fold === 0) res = `\n${indent}${text.slice(0, end)}`;
			else {
				if (mode === FOLD_QUOTED && escapedFolds[fold]) res += `${text[fold]}\\`;
				res += `\n${indent}${text.slice(fold + 1, end)}`;
			}
		}
		return res;
	}
	/**
	* Presumes `i + 1` is at the start of a line
	* @returns index of last newline in more-indented block
	*/
	function consumeMoreIndentedLines(text, i, indent) {
		let end = i;
		let start = i + 1;
		let ch = text[start];
		while (ch === " " || ch === "	") if (i < start + indent) ch = text[++i];
		else {
			do
				ch = text[++i];
			while (ch && ch !== "\n");
			end = i;
			start = i + 1;
			ch = text[start];
		}
		return end;
	}
	exports.FOLD_BLOCK = FOLD_BLOCK;
	exports.FOLD_FLOW = FOLD_FLOW;
	exports.FOLD_QUOTED = FOLD_QUOTED;
	exports.foldFlowLines = foldFlowLines;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringifyString.js
var require_stringifyString = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	var foldFlowLines = require_foldFlowLines();
	const getFoldOptions = (ctx, isBlock) => ({
		indentAtStart: isBlock ? ctx.indent.length : ctx.indentAtStart,
		lineWidth: ctx.options.lineWidth,
		minContentWidth: ctx.options.minContentWidth
	});
	const containsDocumentMarker = (str) => /^(%|---|\.\.\.)/m.test(str);
	function lineLengthOverLimit(str, lineWidth, indentLength) {
		if (!lineWidth || lineWidth < 0) return false;
		const limit = lineWidth - indentLength;
		const strLen = str.length;
		if (strLen <= limit) return false;
		for (let i = 0, start = 0; i < strLen; ++i) if (str[i] === "\n") {
			if (i - start > limit) return true;
			start = i + 1;
			if (strLen - start <= limit) return false;
		}
		return true;
	}
	function doubleQuotedString(value, ctx) {
		const json = JSON.stringify(value);
		if (ctx.options.doubleQuotedAsJSON) return json;
		const { implicitKey } = ctx;
		const minMultiLineLength = ctx.options.doubleQuotedMinMultiLineLength;
		const indent = ctx.indent || (containsDocumentMarker(value) ? "  " : "");
		let str = "";
		let start = 0;
		for (let i = 0, ch = json[i]; ch; ch = json[++i]) {
			if (ch === " " && json[i + 1] === "\\" && json[i + 2] === "n") {
				str += json.slice(start, i) + "\\ ";
				i += 1;
				start = i;
				ch = "\\";
			}
			if (ch === "\\") switch (json[i + 1]) {
				case "u":
					{
						str += json.slice(start, i);
						const code = json.substr(i + 2, 4);
						switch (code) {
							case "0000":
								str += "\\0";
								break;
							case "0007":
								str += "\\a";
								break;
							case "000b":
								str += "\\v";
								break;
							case "001b":
								str += "\\e";
								break;
							case "0085":
								str += "\\N";
								break;
							case "00a0":
								str += "\\_";
								break;
							case "2028":
								str += "\\L";
								break;
							case "2029":
								str += "\\P";
								break;
							default: if (code.substr(0, 2) === "00") str += "\\x" + code.substr(2);
							else str += json.substr(i, 6);
						}
						i += 5;
						start = i + 1;
					}
					break;
				case "n":
					if (implicitKey || json[i + 2] === "\"" || json.length < minMultiLineLength) i += 1;
					else {
						str += json.slice(start, i) + "\n\n";
						while (json[i + 2] === "\\" && json[i + 3] === "n" && json[i + 4] !== "\"") {
							str += "\n";
							i += 2;
						}
						str += indent;
						if (json[i + 2] === " ") str += "\\";
						i += 1;
						start = i + 1;
					}
					break;
				default: i += 1;
			}
		}
		str = start ? str + json.slice(start) : json;
		return implicitKey ? str : foldFlowLines.foldFlowLines(str, indent, foldFlowLines.FOLD_QUOTED, getFoldOptions(ctx, false));
	}
	function singleQuotedString(value, ctx) {
		if (ctx.options.singleQuote === false || ctx.implicitKey && value.includes("\n") || /[ \t]\n|\n[ \t]/.test(value)) return doubleQuotedString(value, ctx);
		const indent = ctx.indent || (containsDocumentMarker(value) ? "  " : "");
		const res = "'" + value.replace(/'/g, "''").replace(/\n+/g, `$&\n${indent}`) + "'";
		return ctx.implicitKey ? res : foldFlowLines.foldFlowLines(res, indent, foldFlowLines.FOLD_FLOW, getFoldOptions(ctx, false));
	}
	function quotedString(value, ctx) {
		const { singleQuote } = ctx.options;
		let qs;
		if (singleQuote === false) qs = doubleQuotedString;
		else {
			const hasDouble = value.includes("\"");
			const hasSingle = value.includes("'");
			if (hasDouble && !hasSingle) qs = singleQuotedString;
			else if (hasSingle && !hasDouble) qs = doubleQuotedString;
			else qs = singleQuote ? singleQuotedString : doubleQuotedString;
		}
		return qs(value, ctx);
	}
	let blockEndNewlines;
	try {
		blockEndNewlines = /* @__PURE__ */ new RegExp("(^|(?<!\n))\n+(?!\n|$)", "g");
	} catch {
		blockEndNewlines = /\n+(?!\n|$)/g;
	}
	function blockString({ comment, type, value }, ctx, onComment, onChompKeep) {
		const { blockQuote, commentString, lineWidth } = ctx.options;
		if (!blockQuote || /\n[\t ]+$/.test(value)) return quotedString(value, ctx);
		const indent = ctx.indent || (ctx.forceBlockIndent || containsDocumentMarker(value) ? "  " : "");
		const literal = blockQuote === "literal" ? true : blockQuote === "folded" || type === Scalar.Scalar.BLOCK_FOLDED ? false : type === Scalar.Scalar.BLOCK_LITERAL ? true : !lineLengthOverLimit(value, lineWidth, indent.length);
		if (!value) return literal ? "|\n" : ">\n";
		let chomp;
		let endStart;
		for (endStart = value.length; endStart > 0; --endStart) {
			const ch = value[endStart - 1];
			if (ch !== "\n" && ch !== "	" && ch !== " ") break;
		}
		let end = value.substring(endStart);
		const endNlPos = end.indexOf("\n");
		if (endNlPos === -1) chomp = "-";
		else if (value === end || endNlPos !== end.length - 1) {
			chomp = "+";
			if (onChompKeep) onChompKeep();
		} else chomp = "";
		if (end) {
			value = value.slice(0, -end.length);
			if (end[end.length - 1] === "\n") end = end.slice(0, -1);
			end = end.replace(blockEndNewlines, `$&${indent}`);
		}
		let startWithSpace = false;
		let startEnd;
		let startNlPos = -1;
		for (startEnd = 0; startEnd < value.length; ++startEnd) {
			const ch = value[startEnd];
			if (ch === " ") startWithSpace = true;
			else if (ch === "\n") startNlPos = startEnd;
			else break;
		}
		let start = value.substring(0, startNlPos < startEnd ? startNlPos + 1 : startEnd);
		if (start) {
			value = value.substring(start.length);
			start = start.replace(/\n+/g, `$&${indent}`);
		}
		let header = (startWithSpace ? indent ? "2" : "1" : "") + chomp;
		if (comment) {
			header += " " + commentString(comment.replace(/ ?[\r\n]+/g, " "));
			if (onComment) onComment();
		}
		if (!literal) {
			const foldedValue = value.replace(/\n+/g, "\n$&").replace(/(?:^|\n)([\t ].*)(?:([\n\t ]*)\n(?![\n\t ]))?/g, "$1$2").replace(/\n+/g, `$&${indent}`);
			let literalFallback = false;
			const foldOptions = getFoldOptions(ctx, true);
			if (blockQuote !== "folded" && type !== Scalar.Scalar.BLOCK_FOLDED) foldOptions.onOverflow = () => {
				literalFallback = true;
			};
			const body = foldFlowLines.foldFlowLines(`${start}${foldedValue}${end}`, indent, foldFlowLines.FOLD_BLOCK, foldOptions);
			if (!literalFallback) return `>${header}\n${indent}${body}`;
		}
		value = value.replace(/\n+/g, `$&${indent}`);
		return `|${header}\n${indent}${start}${value}${end}`;
	}
	function plainString(item, ctx, onComment, onChompKeep) {
		const { type, value } = item;
		const { actualString, implicitKey, indent, indentStep, inFlow } = ctx;
		if (implicitKey && value.includes("\n") || inFlow && /[[\]{},]/.test(value)) return quotedString(value, ctx);
		if (/^[\n\t ,[\]{}#&*!|>'"%@`]|^[?-]$|^[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]$/.test(value)) return implicitKey || inFlow || !value.includes("\n") ? quotedString(value, ctx) : blockString(item, ctx, onComment, onChompKeep);
		if (!implicitKey && !inFlow && type !== Scalar.Scalar.PLAIN && value.includes("\n")) return blockString(item, ctx, onComment, onChompKeep);
		if (containsDocumentMarker(value)) {
			if (indent === "") {
				ctx.forceBlockIndent = true;
				return blockString(item, ctx, onComment, onChompKeep);
			} else if (implicitKey && indent === indentStep) return quotedString(value, ctx);
		}
		const str = value.replace(/\n+/g, `$&\n${indent}`);
		if (actualString) {
			const test = (tag) => tag.default && tag.tag !== "tag:yaml.org,2002:str" && tag.test?.test(str);
			const { compat, tags } = ctx.doc.schema;
			if (tags.some(test) || compat?.some(test)) return quotedString(value, ctx);
		}
		return implicitKey ? str : foldFlowLines.foldFlowLines(str, indent, foldFlowLines.FOLD_FLOW, getFoldOptions(ctx, false));
	}
	function stringifyString(item, ctx, onComment, onChompKeep) {
		const { implicitKey, inFlow } = ctx;
		const ss = typeof item.value === "string" ? item : Object.assign({}, item, { value: String(item.value) });
		let { type } = item;
		if (type !== Scalar.Scalar.QUOTE_DOUBLE) {
			if (/[\x00-\x08\x0b-\x1f\x7f-\x9f\u{D800}-\u{DFFF}]/u.test(ss.value)) type = Scalar.Scalar.QUOTE_DOUBLE;
		}
		const _stringify = (_type) => {
			switch (_type) {
				case Scalar.Scalar.BLOCK_FOLDED:
				case Scalar.Scalar.BLOCK_LITERAL: return implicitKey || inFlow ? quotedString(ss.value, ctx) : blockString(ss, ctx, onComment, onChompKeep);
				case Scalar.Scalar.QUOTE_DOUBLE: return doubleQuotedString(ss.value, ctx);
				case Scalar.Scalar.QUOTE_SINGLE: return singleQuotedString(ss.value, ctx);
				case Scalar.Scalar.PLAIN: return plainString(ss, ctx, onComment, onChompKeep);
				default: return null;
			}
		};
		let res = _stringify(type);
		if (res === null) {
			const { defaultKeyType, defaultStringType } = ctx.options;
			const t = implicitKey && defaultKeyType || defaultStringType;
			res = _stringify(t);
			if (res === null) throw new Error(`Unsupported default string type ${t}`);
		}
		return res;
	}
	exports.stringifyString = stringifyString;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringify.js
var require_stringify = /* @__PURE__ */ __commonJSMin(((exports) => {
	var anchors = require_anchors();
	var identity = require_identity();
	var stringifyComment = require_stringifyComment();
	var stringifyString = require_stringifyString();
	function createStringifyContext(doc, options) {
		const opt = Object.assign({
			blockQuote: true,
			commentString: stringifyComment.stringifyComment,
			defaultKeyType: null,
			defaultStringType: "PLAIN",
			directives: null,
			doubleQuotedAsJSON: false,
			doubleQuotedMinMultiLineLength: 40,
			falseStr: "false",
			flowCollectionPadding: true,
			indentSeq: true,
			lineWidth: 80,
			minContentWidth: 20,
			nullStr: "null",
			simpleKeys: false,
			singleQuote: null,
			trailingComma: false,
			trueStr: "true",
			verifyAliasOrder: true
		}, doc.schema.toStringOptions, options);
		let inFlow;
		switch (opt.collectionStyle) {
			case "block":
				inFlow = false;
				break;
			case "flow":
				inFlow = true;
				break;
			default: inFlow = null;
		}
		return {
			anchors: /* @__PURE__ */ new Set(),
			doc,
			flowCollectionPadding: opt.flowCollectionPadding ? " " : "",
			indent: "",
			indentStep: typeof opt.indent === "number" ? " ".repeat(opt.indent) : "  ",
			inFlow,
			options: opt
		};
	}
	function getTagObject(tags, item) {
		if (item.tag) {
			const match = tags.filter((t) => t.tag === item.tag);
			if (match.length > 0) return match.find((t) => t.format === item.format) ?? match[0];
		}
		let tagObj = void 0;
		let obj;
		if (identity.isScalar(item)) {
			obj = item.value;
			let match = tags.filter((t) => t.identify?.(obj));
			if (match.length > 1) {
				const testMatch = match.filter((t) => t.test);
				if (testMatch.length > 0) match = testMatch;
			}
			tagObj = match.find((t) => t.format === item.format) ?? match.find((t) => !t.format);
		} else {
			obj = item;
			tagObj = tags.find((t) => t.nodeClass && obj instanceof t.nodeClass);
		}
		if (!tagObj) {
			const name = obj?.constructor?.name ?? (obj === null ? "null" : typeof obj);
			throw new Error(`Tag not resolved for ${name} value`);
		}
		return tagObj;
	}
	function stringifyProps(node, tagObj, { anchors: anchors$1, doc }) {
		if (!doc.directives) return "";
		const props = [];
		const anchor = (identity.isScalar(node) || identity.isCollection(node)) && node.anchor;
		if (anchor && anchors.anchorIsValid(anchor)) {
			anchors$1.add(anchor);
			props.push(`&${anchor}`);
		}
		const tag = node.tag ?? (tagObj.default ? null : tagObj.tag);
		if (tag) props.push(doc.directives.tagString(tag));
		return props.join(" ");
	}
	function stringify(item, ctx, onComment, onChompKeep) {
		if (identity.isPair(item)) return item.toString(ctx, onComment, onChompKeep);
		if (identity.isAlias(item)) {
			if (ctx.doc.directives) return item.toString(ctx);
			if (ctx.resolvedAliases?.has(item)) throw new TypeError(`Cannot stringify circular structure without alias nodes`);
			else {
				if (ctx.resolvedAliases) ctx.resolvedAliases.add(item);
				else ctx.resolvedAliases = /* @__PURE__ */ new Set([item]);
				item = item.resolve(ctx.doc);
			}
		}
		let tagObj = void 0;
		const node = identity.isNode(item) ? item : ctx.doc.createNode(item, { onTagObj: (o) => tagObj = o });
		tagObj ?? (tagObj = getTagObject(ctx.doc.schema.tags, node));
		const props = stringifyProps(node, tagObj, ctx);
		if (props.length > 0) ctx.indentAtStart = (ctx.indentAtStart ?? 0) + props.length + 1;
		const str = typeof tagObj.stringify === "function" ? tagObj.stringify(node, ctx, onComment, onChompKeep) : identity.isScalar(node) ? stringifyString.stringifyString(node, ctx, onComment, onChompKeep) : node.toString(ctx, onComment, onChompKeep);
		if (!props) return str;
		return identity.isScalar(node) || str[0] === "{" || str[0] === "[" ? `${props} ${str}` : `${props}\n${ctx.indent}${str}`;
	}
	exports.createStringifyContext = createStringifyContext;
	exports.stringify = stringify;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringifyPair.js
var require_stringifyPair = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Scalar = require_Scalar();
	var stringify = require_stringify();
	var stringifyComment = require_stringifyComment();
	function stringifyPair({ key, value }, ctx, onComment, onChompKeep) {
		const { allNullValues, doc, indent, indentStep, options: { commentString, indentSeq, simpleKeys } } = ctx;
		let keyComment = identity.isNode(key) && key.comment || null;
		if (simpleKeys) {
			if (keyComment) throw new Error("With simple keys, key nodes cannot have comments");
			if (identity.isCollection(key) || !identity.isNode(key) && typeof key === "object") throw new Error("With simple keys, collection cannot be used as a key value");
		}
		let explicitKey = !simpleKeys && (!key || keyComment && value == null && !ctx.inFlow || identity.isCollection(key) || (identity.isScalar(key) ? key.type === Scalar.Scalar.BLOCK_FOLDED || key.type === Scalar.Scalar.BLOCK_LITERAL : typeof key === "object"));
		ctx = Object.assign({}, ctx, {
			allNullValues: false,
			implicitKey: !explicitKey && (simpleKeys || !allNullValues),
			indent: indent + indentStep
		});
		let keyCommentDone = false;
		let chompKeep = false;
		let str = stringify.stringify(key, ctx, () => keyCommentDone = true, () => chompKeep = true);
		if (!explicitKey && !ctx.inFlow && str.length > 1024) {
			if (simpleKeys) throw new Error("With simple keys, single line scalar must not span more than 1024 characters");
			explicitKey = true;
		}
		if (ctx.inFlow) {
			if (allNullValues || value == null) {
				if (keyCommentDone && onComment) onComment();
				return str === "" ? "?" : explicitKey ? `? ${str}` : str;
			}
		} else if (allNullValues && !simpleKeys || value == null && explicitKey) {
			str = `? ${str}`;
			if (keyComment && !keyCommentDone) str += stringifyComment.lineComment(str, ctx.indent, commentString(keyComment));
			else if (chompKeep && onChompKeep) onChompKeep();
			return str;
		}
		if (keyCommentDone) keyComment = null;
		if (explicitKey) {
			if (keyComment) str += stringifyComment.lineComment(str, ctx.indent, commentString(keyComment));
			str = `? ${str}\n${indent}:`;
		} else {
			str = `${str}:`;
			if (keyComment) str += stringifyComment.lineComment(str, ctx.indent, commentString(keyComment));
		}
		let vsb, vcb, valueComment;
		if (identity.isNode(value)) {
			vsb = !!value.spaceBefore;
			vcb = value.commentBefore;
			valueComment = value.comment;
		} else {
			vsb = false;
			vcb = null;
			valueComment = null;
			if (value && typeof value === "object") value = doc.createNode(value);
		}
		ctx.implicitKey = false;
		if (!explicitKey && !keyComment && identity.isScalar(value)) ctx.indentAtStart = str.length + 1;
		chompKeep = false;
		if (!indentSeq && indentStep.length >= 2 && !ctx.inFlow && !explicitKey && identity.isSeq(value) && !value.flow && !value.tag && !value.anchor) ctx.indent = ctx.indent.substring(2);
		let valueCommentDone = false;
		const valueStr = stringify.stringify(value, ctx, () => valueCommentDone = true, () => chompKeep = true);
		let ws = " ";
		if (keyComment || vsb || vcb) {
			ws = vsb ? "\n" : "";
			if (vcb) {
				const cs = commentString(vcb);
				ws += `\n${stringifyComment.indentComment(cs, ctx.indent)}`;
			}
			if (valueStr === "" && !ctx.inFlow) {
				if (ws === "\n" && valueComment) ws = "\n\n";
			} else ws += `\n${ctx.indent}`;
		} else if (!explicitKey && identity.isCollection(value)) {
			const vs0 = valueStr[0];
			const nl0 = valueStr.indexOf("\n");
			const hasNewline = nl0 !== -1;
			const flow = ctx.inFlow ?? value.flow ?? value.items.length === 0;
			if (hasNewline || !flow) {
				let hasPropsLine = false;
				if (hasNewline && (vs0 === "&" || vs0 === "!")) {
					let sp0 = valueStr.indexOf(" ");
					if (vs0 === "&" && sp0 !== -1 && sp0 < nl0 && valueStr[sp0 + 1] === "!") sp0 = valueStr.indexOf(" ", sp0 + 1);
					if (sp0 === -1 || nl0 < sp0) hasPropsLine = true;
				}
				if (!hasPropsLine) ws = `\n${ctx.indent}`;
			}
		} else if (valueStr === "" || valueStr[0] === "\n") ws = "";
		str += ws + valueStr;
		if (ctx.inFlow) {
			if (valueCommentDone && onComment) onComment();
		} else if (valueComment && !valueCommentDone) str += stringifyComment.lineComment(str, ctx.indent, commentString(valueComment));
		else if (chompKeep && onChompKeep) onChompKeep();
		return str;
	}
	exports.stringifyPair = stringifyPair;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/log.js
var require_log = /* @__PURE__ */ __commonJSMin(((exports) => {
	var node_process = __require("process");
	function debug(logLevel, ...messages) {
		if (logLevel === "debug") console.log(...messages);
	}
	function warn(logLevel, warning) {
		if (logLevel === "debug" || logLevel === "warn") {
			if (typeof node_process.emitWarning === "function") node_process.emitWarning(warning);
			else console.warn(warning);
		}
	}
	exports.debug = debug;
	exports.warn = warn;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/merge.js
var require_merge = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Scalar = require_Scalar();
	const MERGE_KEY = "<<";
	const merge = {
		identify: (value) => value === MERGE_KEY || typeof value === "symbol" && value.description === MERGE_KEY,
		default: "key",
		tag: "tag:yaml.org,2002:merge",
		test: /^<<$/,
		resolve: () => Object.assign(new Scalar.Scalar(Symbol(MERGE_KEY)), { addToJSMap: addMergeToJSMap }),
		stringify: () => MERGE_KEY
	};
	const isMergeKey = (ctx, key) => (merge.identify(key) || identity.isScalar(key) && (!key.type || key.type === Scalar.Scalar.PLAIN) && merge.identify(key.value)) && ctx?.doc.schema.tags.some((tag) => tag.tag === merge.tag && tag.default);
	function addMergeToJSMap(ctx, map, value) {
		const source = resolveAliasValue(ctx, value);
		if (identity.isSeq(source)) for (const it of source.items) mergeValue(ctx, map, it);
		else if (Array.isArray(source)) for (const it of source) mergeValue(ctx, map, it);
		else mergeValue(ctx, map, source);
	}
	function mergeValue(ctx, map, value) {
		const source = resolveAliasValue(ctx, value);
		if (!identity.isMap(source)) throw new Error("Merge sources must be maps or map aliases");
		const srcMap = source.toJSON(null, ctx, Map);
		for (const [key, value] of srcMap) if (map instanceof Map) {
			if (!map.has(key)) map.set(key, value);
		} else if (map instanceof Set) map.add(key);
		else if (!Object.prototype.hasOwnProperty.call(map, key)) Object.defineProperty(map, key, {
			value,
			writable: true,
			enumerable: true,
			configurable: true
		});
		return map;
	}
	function resolveAliasValue(ctx, value) {
		return ctx && identity.isAlias(value) ? value.resolve(ctx.doc, ctx) : value;
	}
	exports.addMergeToJSMap = addMergeToJSMap;
	exports.isMergeKey = isMergeKey;
	exports.merge = merge;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/addPairToJSMap.js
var require_addPairToJSMap = /* @__PURE__ */ __commonJSMin(((exports) => {
	var log = require_log();
	var merge = require_merge();
	var stringify = require_stringify();
	var identity = require_identity();
	var toJS = require_toJS();
	function addPairToJSMap(ctx, map, { key, value }) {
		if (identity.isNode(key) && key.addToJSMap) key.addToJSMap(ctx, map, value);
		else if (merge.isMergeKey(ctx, key)) merge.addMergeToJSMap(ctx, map, value);
		else {
			const jsKey = toJS.toJS(key, "", ctx);
			if (map instanceof Map) map.set(jsKey, toJS.toJS(value, jsKey, ctx));
			else if (map instanceof Set) map.add(jsKey);
			else {
				const stringKey = stringifyKey(key, jsKey, ctx);
				const jsValue = toJS.toJS(value, stringKey, ctx);
				if (stringKey in map) Object.defineProperty(map, stringKey, {
					value: jsValue,
					writable: true,
					enumerable: true,
					configurable: true
				});
				else map[stringKey] = jsValue;
			}
		}
		return map;
	}
	function stringifyKey(key, jsKey, ctx) {
		if (jsKey === null) return "";
		if (typeof jsKey !== "object") return String(jsKey);
		if (identity.isNode(key) && ctx?.doc) {
			const strCtx = stringify.createStringifyContext(ctx.doc, {});
			strCtx.anchors = /* @__PURE__ */ new Set();
			for (const node of ctx.anchors.keys()) strCtx.anchors.add(node.anchor);
			strCtx.inFlow = true;
			strCtx.inStringifyKey = true;
			const strKey = key.toString(strCtx);
			if (!ctx.mapKeyWarned) {
				let jsonStr = JSON.stringify(strKey);
				if (jsonStr.length > 40) jsonStr = jsonStr.substring(0, 36) + "...\"";
				log.warn(ctx.doc.options.logLevel, `Keys with collection values will be stringified due to JS Object restrictions: ${jsonStr}. Set mapAsMap: true to use object keys.`);
				ctx.mapKeyWarned = true;
			}
			return strKey;
		}
		return JSON.stringify(jsKey);
	}
	exports.addPairToJSMap = addPairToJSMap;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/Pair.js
var require_Pair = /* @__PURE__ */ __commonJSMin(((exports) => {
	var createNode = require_createNode();
	var stringifyPair = require_stringifyPair();
	var addPairToJSMap = require_addPairToJSMap();
	var identity = require_identity();
	function createPair(key, value, ctx) {
		return new Pair(createNode.createNode(key, void 0, ctx), createNode.createNode(value, void 0, ctx));
	}
	var Pair = class Pair {
		constructor(key, value = null) {
			Object.defineProperty(this, identity.NODE_TYPE, { value: identity.PAIR });
			this.key = key;
			this.value = value;
		}
		clone(schema) {
			let { key, value } = this;
			if (identity.isNode(key)) key = key.clone(schema);
			if (identity.isNode(value)) value = value.clone(schema);
			return new Pair(key, value);
		}
		toJSON(_, ctx) {
			const pair = ctx?.mapAsMap ? /* @__PURE__ */ new Map() : {};
			return addPairToJSMap.addPairToJSMap(ctx, pair, this);
		}
		toString(ctx, onComment, onChompKeep) {
			return ctx?.doc ? stringifyPair.stringifyPair(this, ctx, onComment, onChompKeep) : JSON.stringify(this);
		}
	};
	exports.Pair = Pair;
	exports.createPair = createPair;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringifyCollection.js
var require_stringifyCollection = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var stringify = require_stringify();
	var stringifyComment = require_stringifyComment();
	function stringifyCollection(collection, ctx, options) {
		return (ctx.inFlow ?? collection.flow ? stringifyFlowCollection : stringifyBlockCollection)(collection, ctx, options);
	}
	function stringifyBlockCollection({ comment, items }, ctx, { blockItemPrefix, flowChars, itemIndent, onChompKeep, onComment }) {
		const { indent, options: { commentString } } = ctx;
		const itemCtx = Object.assign({}, ctx, {
			indent: itemIndent,
			type: null
		});
		let chompKeep = false;
		const lines = [];
		for (let i = 0; i < items.length; ++i) {
			const item = items[i];
			let comment = null;
			if (identity.isNode(item)) {
				if (!chompKeep && item.spaceBefore) lines.push("");
				addCommentBefore(ctx, lines, item.commentBefore, chompKeep);
				if (item.comment) comment = item.comment;
			} else if (identity.isPair(item)) {
				const ik = identity.isNode(item.key) ? item.key : null;
				if (ik) {
					if (!chompKeep && ik.spaceBefore) lines.push("");
					addCommentBefore(ctx, lines, ik.commentBefore, chompKeep);
				}
			}
			chompKeep = false;
			let str = stringify.stringify(item, itemCtx, () => comment = null, () => chompKeep = true);
			if (comment) str += stringifyComment.lineComment(str, itemIndent, commentString(comment));
			if (chompKeep && comment) chompKeep = false;
			lines.push(blockItemPrefix + str);
		}
		let str;
		if (lines.length === 0) str = flowChars.start + flowChars.end;
		else {
			str = lines[0];
			for (let i = 1; i < lines.length; ++i) {
				const line = lines[i];
				str += line ? `\n${indent}${line}` : "\n";
			}
		}
		if (comment) {
			str += "\n" + stringifyComment.indentComment(commentString(comment), indent);
			if (onComment) onComment();
		} else if (chompKeep && onChompKeep) onChompKeep();
		return str;
	}
	function stringifyFlowCollection({ items }, ctx, { flowChars, itemIndent }) {
		const { indent, indentStep, flowCollectionPadding: fcPadding, options: { commentString } } = ctx;
		itemIndent += indentStep;
		const itemCtx = Object.assign({}, ctx, {
			indent: itemIndent,
			inFlow: true,
			type: null
		});
		let reqNewline = false;
		let linesAtValue = 0;
		const lines = [];
		for (let i = 0; i < items.length; ++i) {
			const item = items[i];
			let comment = null;
			if (identity.isNode(item)) {
				if (item.spaceBefore) lines.push("");
				addCommentBefore(ctx, lines, item.commentBefore, false);
				if (item.comment) comment = item.comment;
			} else if (identity.isPair(item)) {
				const ik = identity.isNode(item.key) ? item.key : null;
				if (ik) {
					if (ik.spaceBefore) lines.push("");
					addCommentBefore(ctx, lines, ik.commentBefore, false);
					if (ik.comment) reqNewline = true;
				}
				const iv = identity.isNode(item.value) ? item.value : null;
				if (iv) {
					if (iv.comment) comment = iv.comment;
					if (iv.commentBefore) reqNewline = true;
				} else if (item.value == null && ik?.comment) comment = ik.comment;
			}
			if (comment) reqNewline = true;
			let str = stringify.stringify(item, itemCtx, () => comment = null);
			reqNewline || (reqNewline = lines.length > linesAtValue || str.includes("\n"));
			if (i < items.length - 1) str += ",";
			else if (ctx.options.trailingComma) {
				if (ctx.options.lineWidth > 0) reqNewline || (reqNewline = lines.reduce((sum, line) => sum + line.length + 2, 2) + (str.length + 2) > ctx.options.lineWidth);
				if (reqNewline) str += ",";
			}
			if (comment) str += stringifyComment.lineComment(str, itemIndent, commentString(comment));
			lines.push(str);
			linesAtValue = lines.length;
		}
		const { start, end } = flowChars;
		if (lines.length === 0) return start + end;
		else {
			if (!reqNewline) {
				const len = lines.reduce((sum, line) => sum + line.length + 2, 2);
				reqNewline = ctx.options.lineWidth > 0 && len > ctx.options.lineWidth;
			}
			if (reqNewline) {
				let str = start;
				for (const line of lines) str += line ? `\n${indentStep}${indent}${line}` : "\n";
				return `${str}\n${indent}${end}`;
			} else return `${start}${fcPadding}${lines.join(" ")}${fcPadding}${end}`;
		}
	}
	function addCommentBefore({ indent, options: { commentString } }, lines, comment, chompKeep) {
		if (comment && chompKeep) comment = comment.replace(/^\n+/, "");
		if (comment) {
			const ic = stringifyComment.indentComment(commentString(comment), indent);
			lines.push(ic.trimStart());
		}
	}
	exports.stringifyCollection = stringifyCollection;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/YAMLMap.js
var require_YAMLMap = /* @__PURE__ */ __commonJSMin(((exports) => {
	var stringifyCollection = require_stringifyCollection();
	var addPairToJSMap = require_addPairToJSMap();
	var Collection = require_Collection();
	var identity = require_identity();
	var Pair = require_Pair();
	var Scalar = require_Scalar();
	function findPair(items, key) {
		const k = identity.isScalar(key) ? key.value : key;
		for (const it of items) if (identity.isPair(it)) {
			if (it.key === key || it.key === k) return it;
			if (identity.isScalar(it.key) && it.key.value === k) return it;
		}
	}
	var YAMLMap = class extends Collection.Collection {
		static get tagName() {
			return "tag:yaml.org,2002:map";
		}
		constructor(schema) {
			super(identity.MAP, schema);
			this.items = [];
		}
		/**
		* A generic collection parsing method that can be extended
		* to other node classes that inherit from YAMLMap
		*/
		static from(schema, obj, ctx) {
			const { keepUndefined, replacer } = ctx;
			const map = new this(schema);
			const add = (key, value) => {
				if (typeof replacer === "function") value = replacer.call(obj, key, value);
				else if (Array.isArray(replacer) && !replacer.includes(key)) return;
				if (value !== void 0 || keepUndefined) map.items.push(Pair.createPair(key, value, ctx));
			};
			if (obj instanceof Map) for (const [key, value] of obj) add(key, value);
			else if (obj && typeof obj === "object") for (const key of Object.keys(obj)) add(key, obj[key]);
			if (typeof schema.sortMapEntries === "function") map.items.sort(schema.sortMapEntries);
			return map;
		}
		/**
		* Adds a value to the collection.
		*
		* @param overwrite - If not set `true`, using a key that is already in the
		*   collection will throw. Otherwise, overwrites the previous value.
		*/
		add(pair, overwrite) {
			let _pair;
			if (identity.isPair(pair)) _pair = pair;
			else if (!pair || typeof pair !== "object" || !("key" in pair)) _pair = new Pair.Pair(pair, pair?.value);
			else _pair = new Pair.Pair(pair.key, pair.value);
			const prev = findPair(this.items, _pair.key);
			const sortEntries = this.schema?.sortMapEntries;
			if (prev) {
				if (!overwrite) throw new Error(`Key ${_pair.key} already set`);
				if (identity.isScalar(prev.value) && Scalar.isScalarValue(_pair.value)) prev.value.value = _pair.value;
				else prev.value = _pair.value;
			} else if (sortEntries) {
				const i = this.items.findIndex((item) => sortEntries(_pair, item) < 0);
				if (i === -1) this.items.push(_pair);
				else this.items.splice(i, 0, _pair);
			} else this.items.push(_pair);
		}
		delete(key) {
			const it = findPair(this.items, key);
			if (!it) return false;
			return this.items.splice(this.items.indexOf(it), 1).length > 0;
		}
		get(key, keepScalar) {
			const node = findPair(this.items, key)?.value;
			return (!keepScalar && identity.isScalar(node) ? node.value : node) ?? void 0;
		}
		has(key) {
			return !!findPair(this.items, key);
		}
		set(key, value) {
			this.add(new Pair.Pair(key, value), true);
		}
		/**
		* @param ctx - Conversion context, originally set in Document#toJS()
		* @param {Class} Type - If set, forces the returned collection type
		* @returns Instance of Type, Map, or Object
		*/
		toJSON(_, ctx, Type) {
			const map = Type ? new Type() : ctx?.mapAsMap ? /* @__PURE__ */ new Map() : {};
			if (ctx?.onCreate) ctx.onCreate(map);
			for (const item of this.items) addPairToJSMap.addPairToJSMap(ctx, map, item);
			return map;
		}
		toString(ctx, onComment, onChompKeep) {
			if (!ctx) return JSON.stringify(this);
			for (const item of this.items) if (!identity.isPair(item)) throw new Error(`Map items must all be pairs; found ${JSON.stringify(item)} instead`);
			if (!ctx.allNullValues && this.hasAllNullValues(false)) ctx = Object.assign({}, ctx, { allNullValues: true });
			return stringifyCollection.stringifyCollection(this, ctx, {
				blockItemPrefix: "",
				flowChars: {
					start: "{",
					end: "}"
				},
				itemIndent: ctx.indent || "",
				onChompKeep,
				onComment
			});
		}
	};
	exports.YAMLMap = YAMLMap;
	exports.findPair = findPair;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/common/map.js
var require_map = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var YAMLMap = require_YAMLMap();
	exports.map = {
		collection: "map",
		default: true,
		nodeClass: YAMLMap.YAMLMap,
		tag: "tag:yaml.org,2002:map",
		resolve(map, onError) {
			if (!identity.isMap(map)) onError("Expected a mapping for this tag");
			return map;
		},
		createNode: (schema, obj, ctx) => YAMLMap.YAMLMap.from(schema, obj, ctx)
	};
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/nodes/YAMLSeq.js
var require_YAMLSeq = /* @__PURE__ */ __commonJSMin(((exports) => {
	var createNode = require_createNode();
	var stringifyCollection = require_stringifyCollection();
	var Collection = require_Collection();
	var identity = require_identity();
	var Scalar = require_Scalar();
	var toJS = require_toJS();
	var YAMLSeq = class extends Collection.Collection {
		static get tagName() {
			return "tag:yaml.org,2002:seq";
		}
		constructor(schema) {
			super(identity.SEQ, schema);
			this.items = [];
		}
		add(value) {
			this.items.push(value);
		}
		/**
		* Removes a value from the collection.
		*
		* `key` must contain a representation of an integer for this to succeed.
		* It may be wrapped in a `Scalar`.
		*
		* @returns `true` if the item was found and removed.
		*/
		delete(key) {
			const idx = asItemIndex(key);
			if (typeof idx !== "number") return false;
			return this.items.splice(idx, 1).length > 0;
		}
		get(key, keepScalar) {
			const idx = asItemIndex(key);
			if (typeof idx !== "number") return void 0;
			const it = this.items[idx];
			return !keepScalar && identity.isScalar(it) ? it.value : it;
		}
		/**
		* Checks if the collection includes a value with the key `key`.
		*
		* `key` must contain a representation of an integer for this to succeed.
		* It may be wrapped in a `Scalar`.
		*/
		has(key) {
			const idx = asItemIndex(key);
			return typeof idx === "number" && idx < this.items.length;
		}
		/**
		* Sets a value in this collection. For `!!set`, `value` needs to be a
		* boolean to add/remove the item from the set.
		*
		* If `key` does not contain a representation of an integer, this will throw.
		* It may be wrapped in a `Scalar`.
		*/
		set(key, value) {
			const idx = asItemIndex(key);
			if (typeof idx !== "number") throw new Error(`Expected a valid index, not ${key}.`);
			const prev = this.items[idx];
			if (identity.isScalar(prev) && Scalar.isScalarValue(value)) prev.value = value;
			else this.items[idx] = value;
		}
		toJSON(_, ctx) {
			const seq = [];
			if (ctx?.onCreate) ctx.onCreate(seq);
			let i = 0;
			for (const item of this.items) seq.push(toJS.toJS(item, String(i++), ctx));
			return seq;
		}
		toString(ctx, onComment, onChompKeep) {
			if (!ctx) return JSON.stringify(this);
			return stringifyCollection.stringifyCollection(this, ctx, {
				blockItemPrefix: "- ",
				flowChars: {
					start: "[",
					end: "]"
				},
				itemIndent: (ctx.indent || "") + "  ",
				onChompKeep,
				onComment
			});
		}
		static from(schema, obj, ctx) {
			const { replacer } = ctx;
			const seq = new this(schema);
			if (obj && Symbol.iterator in Object(obj)) {
				let i = 0;
				for (let it of obj) {
					if (typeof replacer === "function") {
						const key = obj instanceof Set ? it : String(i++);
						it = replacer.call(obj, key, it);
					}
					seq.items.push(createNode.createNode(it, void 0, ctx));
				}
			}
			return seq;
		}
	};
	function asItemIndex(key) {
		let idx = identity.isScalar(key) ? key.value : key;
		if (idx && typeof idx === "string") idx = Number(idx);
		return typeof idx === "number" && Number.isInteger(idx) && idx >= 0 ? idx : null;
	}
	exports.YAMLSeq = YAMLSeq;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/common/seq.js
var require_seq = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var YAMLSeq = require_YAMLSeq();
	exports.seq = {
		collection: "seq",
		default: true,
		nodeClass: YAMLSeq.YAMLSeq,
		tag: "tag:yaml.org,2002:seq",
		resolve(seq, onError) {
			if (!identity.isSeq(seq)) onError("Expected a sequence for this tag");
			return seq;
		},
		createNode: (schema, obj, ctx) => YAMLSeq.YAMLSeq.from(schema, obj, ctx)
	};
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/common/string.js
var require_string = /* @__PURE__ */ __commonJSMin(((exports) => {
	var stringifyString = require_stringifyString();
	exports.string = {
		identify: (value) => typeof value === "string",
		default: true,
		tag: "tag:yaml.org,2002:str",
		resolve: (str) => str,
		stringify(item, ctx, onComment, onChompKeep) {
			ctx = Object.assign({ actualString: true }, ctx);
			return stringifyString.stringifyString(item, ctx, onComment, onChompKeep);
		}
	};
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/common/null.js
var require_null = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	const nullTag = {
		identify: (value) => value == null,
		createNode: () => new Scalar.Scalar(null),
		default: true,
		tag: "tag:yaml.org,2002:null",
		test: /^(?:~|[Nn]ull|NULL)?$/,
		resolve: () => new Scalar.Scalar(null),
		stringify: ({ source }, ctx) => typeof source === "string" && nullTag.test.test(source) ? source : ctx.options.nullStr
	};
	exports.nullTag = nullTag;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/core/bool.js
var require_bool$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	const boolTag = {
		identify: (value) => typeof value === "boolean",
		default: true,
		tag: "tag:yaml.org,2002:bool",
		test: /^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)$/,
		resolve: (str) => new Scalar.Scalar(str[0] === "t" || str[0] === "T"),
		stringify({ source, value }, ctx) {
			if (source && boolTag.test.test(source)) {
				if (value === (source[0] === "t" || source[0] === "T")) return source;
			}
			return value ? ctx.options.trueStr : ctx.options.falseStr;
		}
	};
	exports.boolTag = boolTag;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringifyNumber.js
var require_stringifyNumber = /* @__PURE__ */ __commonJSMin(((exports) => {
	function stringifyNumber({ format, minFractionDigits, tag, value }) {
		if (typeof value === "bigint") return String(value);
		const num = typeof value === "number" ? value : Number(value);
		if (!isFinite(num)) return isNaN(num) ? ".nan" : num < 0 ? "-.inf" : ".inf";
		let n = Object.is(value, -0) ? "-0" : JSON.stringify(value);
		if (!format && minFractionDigits && (!tag || tag === "tag:yaml.org,2002:float") && /^-?\d/.test(n) && !n.includes("e")) {
			let i = n.indexOf(".");
			if (i < 0) {
				i = n.length;
				n += ".";
			}
			let d = minFractionDigits - (n.length - i - 1);
			while (d-- > 0) n += "0";
		}
		return n;
	}
	exports.stringifyNumber = stringifyNumber;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/core/float.js
var require_float$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	var stringifyNumber = require_stringifyNumber();
	const floatNaN = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		test: /^(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)$/,
		resolve: (str) => str.slice(-3).toLowerCase() === "nan" ? NaN : str[0] === "-" ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY,
		stringify: stringifyNumber.stringifyNumber
	};
	const floatExp = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		format: "EXP",
		test: /^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+$/,
		resolve: (str) => parseFloat(str),
		stringify(node) {
			const num = Number(node.value);
			return isFinite(num) ? num.toExponential() : stringifyNumber.stringifyNumber(node);
		}
	};
	exports.float = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		test: /^[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)$/,
		resolve(str) {
			const node = new Scalar.Scalar(parseFloat(str));
			const dot = str.indexOf(".");
			if (dot !== -1 && str[str.length - 1] === "0") node.minFractionDigits = str.length - dot - 1;
			return node;
		},
		stringify: stringifyNumber.stringifyNumber
	};
	exports.floatExp = floatExp;
	exports.floatNaN = floatNaN;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/core/int.js
var require_int$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var stringifyNumber = require_stringifyNumber();
	const intIdentify = (value) => typeof value === "bigint" || Number.isInteger(value);
	const intResolve = (str, offset, radix, { intAsBigInt }) => intAsBigInt ? BigInt(str) : parseInt(str.substring(offset), radix);
	function intStringify(node, radix, prefix) {
		const { value } = node;
		if (intIdentify(value) && value >= 0) return prefix + value.toString(radix);
		return stringifyNumber.stringifyNumber(node);
	}
	const intOct = {
		identify: (value) => intIdentify(value) && value >= 0,
		default: true,
		tag: "tag:yaml.org,2002:int",
		format: "OCT",
		test: /^0o[0-7]+$/,
		resolve: (str, _onError, opt) => intResolve(str, 2, 8, opt),
		stringify: (node) => intStringify(node, 8, "0o")
	};
	const int = {
		identify: intIdentify,
		default: true,
		tag: "tag:yaml.org,2002:int",
		test: /^[-+]?[0-9]+$/,
		resolve: (str, _onError, opt) => intResolve(str, 0, 10, opt),
		stringify: stringifyNumber.stringifyNumber
	};
	const intHex = {
		identify: (value) => intIdentify(value) && value >= 0,
		default: true,
		tag: "tag:yaml.org,2002:int",
		format: "HEX",
		test: /^0x[0-9a-fA-F]+$/,
		resolve: (str, _onError, opt) => intResolve(str, 2, 16, opt),
		stringify: (node) => intStringify(node, 16, "0x")
	};
	exports.int = int;
	exports.intHex = intHex;
	exports.intOct = intOct;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/core/schema.js
var require_schema$2 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var map = require_map();
	var _null = require_null();
	var seq = require_seq();
	var string = require_string();
	var bool = require_bool$1();
	var float = require_float$1();
	var int = require_int$1();
	exports.schema = [
		map.map,
		seq.seq,
		string.string,
		_null.nullTag,
		bool.boolTag,
		int.intOct,
		int.int,
		int.intHex,
		float.floatNaN,
		float.floatExp,
		float.float
	];
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/json/schema.js
var require_schema$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	var map = require_map();
	var seq = require_seq();
	function intIdentify(value) {
		return typeof value === "bigint" || Number.isInteger(value);
	}
	const stringifyJSON = ({ value }) => JSON.stringify(value);
	const jsonScalars = [
		{
			identify: (value) => typeof value === "string",
			default: true,
			tag: "tag:yaml.org,2002:str",
			resolve: (str) => str,
			stringify: stringifyJSON
		},
		{
			identify: (value) => value == null,
			createNode: () => new Scalar.Scalar(null),
			default: true,
			tag: "tag:yaml.org,2002:null",
			test: /^null$/,
			resolve: () => null,
			stringify: stringifyJSON
		},
		{
			identify: (value) => typeof value === "boolean",
			default: true,
			tag: "tag:yaml.org,2002:bool",
			test: /^true$|^false$/,
			resolve: (str) => str === "true",
			stringify: stringifyJSON
		},
		{
			identify: intIdentify,
			default: true,
			tag: "tag:yaml.org,2002:int",
			test: /^-?(?:0|[1-9][0-9]*)$/,
			resolve: (str, _onError, { intAsBigInt }) => intAsBigInt ? BigInt(str) : parseInt(str, 10),
			stringify: ({ value }) => intIdentify(value) ? value.toString() : JSON.stringify(value)
		},
		{
			identify: (value) => typeof value === "number",
			default: true,
			tag: "tag:yaml.org,2002:float",
			test: /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:[eE][-+]?[0-9]+)?$/,
			resolve: (str) => parseFloat(str),
			stringify: stringifyJSON
		}
	];
	exports.schema = [map.map, seq.seq].concat(jsonScalars, {
		default: true,
		tag: "",
		test: /^/,
		resolve(str, onError) {
			onError(`Unresolved plain scalar ${JSON.stringify(str)}`);
			return str;
		}
	});
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/binary.js
var require_binary = /* @__PURE__ */ __commonJSMin(((exports) => {
	var node_buffer = __require("buffer");
	var Scalar = require_Scalar();
	var stringifyString = require_stringifyString();
	exports.binary = {
		identify: (value) => value instanceof Uint8Array,
		default: false,
		tag: "tag:yaml.org,2002:binary",
		/**
		* Returns a Buffer in node and an Uint8Array in browsers
		*
		* To use the resulting buffer as an image, you'll want to do something like:
		*
		*   const blob = new Blob([buffer], { type: 'image/jpeg' })
		*   document.querySelector('#photo').src = URL.createObjectURL(blob)
		*/
		resolve(src, onError) {
			if (typeof node_buffer.Buffer === "function") return node_buffer.Buffer.from(src, "base64");
			else if (typeof atob === "function") {
				const str = atob(src.replace(/[\n\r]/g, ""));
				const buffer = new Uint8Array(str.length);
				for (let i = 0; i < str.length; ++i) buffer[i] = str.charCodeAt(i);
				return buffer;
			} else {
				onError("This environment does not support reading binary tags; either Buffer or atob is required");
				return src;
			}
		},
		stringify({ comment, type, value }, ctx, onComment, onChompKeep) {
			if (!value) return "";
			const buf = value;
			let str;
			if (typeof node_buffer.Buffer === "function") str = buf instanceof node_buffer.Buffer ? buf.toString("base64") : node_buffer.Buffer.from(buf.buffer).toString("base64");
			else if (typeof btoa === "function") {
				let s = "";
				for (let i = 0; i < buf.length; ++i) s += String.fromCharCode(buf[i]);
				str = btoa(s);
			} else throw new Error("This environment does not support writing binary tags; either Buffer or btoa is required");
			type ?? (type = Scalar.Scalar.BLOCK_LITERAL);
			if (type !== Scalar.Scalar.QUOTE_DOUBLE) {
				const lineWidth = Math.max(ctx.options.lineWidth - ctx.indent.length, ctx.options.minContentWidth);
				const n = Math.ceil(str.length / lineWidth);
				const lines = new Array(n);
				for (let i = 0, o = 0; i < n; ++i, o += lineWidth) lines[i] = str.substr(o, lineWidth);
				str = lines.join(type === Scalar.Scalar.BLOCK_LITERAL ? "\n" : " ");
			}
			return stringifyString.stringifyString({
				comment,
				type,
				value: str
			}, ctx, onComment, onChompKeep);
		}
	};
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/pairs.js
var require_pairs = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Pair = require_Pair();
	var Scalar = require_Scalar();
	var YAMLSeq = require_YAMLSeq();
	function resolvePairs(seq, onError) {
		if (identity.isSeq(seq)) for (let i = 0; i < seq.items.length; ++i) {
			let item = seq.items[i];
			if (identity.isPair(item)) continue;
			else if (identity.isMap(item)) {
				if (item.items.length > 1) onError("Each pair must have its own sequence indicator");
				const pair = item.items[0] || new Pair.Pair(new Scalar.Scalar(null));
				if (item.commentBefore) pair.key.commentBefore = pair.key.commentBefore ? `${item.commentBefore}\n${pair.key.commentBefore}` : item.commentBefore;
				if (item.comment) {
					const cn = pair.value ?? pair.key;
					cn.comment = cn.comment ? `${item.comment}\n${cn.comment}` : item.comment;
				}
				item = pair;
			}
			seq.items[i] = identity.isPair(item) ? item : new Pair.Pair(item);
		}
		else onError("Expected a sequence for this tag");
		return seq;
	}
	function createPairs(schema, iterable, ctx) {
		const { replacer } = ctx;
		const pairs = new YAMLSeq.YAMLSeq(schema);
		pairs.tag = "tag:yaml.org,2002:pairs";
		let i = 0;
		if (iterable && Symbol.iterator in Object(iterable)) for (let it of iterable) {
			if (typeof replacer === "function") it = replacer.call(iterable, String(i++), it);
			let key, value;
			if (Array.isArray(it)) {
				if (it.length === 2) {
					key = it[0];
					value = it[1];
				} else throw new TypeError(`Expected [key, value] tuple: ${it}`);
			} else if (it && it instanceof Object) {
				const keys = Object.keys(it);
				if (keys.length === 1) {
					key = keys[0];
					value = it[key];
				} else throw new TypeError(`Expected tuple with one key, not ${keys.length} keys`);
			} else key = it;
			pairs.items.push(Pair.createPair(key, value, ctx));
		}
		return pairs;
	}
	const pairs = {
		collection: "seq",
		default: false,
		tag: "tag:yaml.org,2002:pairs",
		resolve: resolvePairs,
		createNode: createPairs
	};
	exports.createPairs = createPairs;
	exports.pairs = pairs;
	exports.resolvePairs = resolvePairs;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/omap.js
var require_omap = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var toJS = require_toJS();
	var YAMLMap = require_YAMLMap();
	var YAMLSeq = require_YAMLSeq();
	var pairs = require_pairs();
	var YAMLOMap = class YAMLOMap extends YAMLSeq.YAMLSeq {
		constructor() {
			super();
			this.add = YAMLMap.YAMLMap.prototype.add.bind(this);
			this.delete = YAMLMap.YAMLMap.prototype.delete.bind(this);
			this.get = YAMLMap.YAMLMap.prototype.get.bind(this);
			this.has = YAMLMap.YAMLMap.prototype.has.bind(this);
			this.set = YAMLMap.YAMLMap.prototype.set.bind(this);
			this.tag = YAMLOMap.tag;
		}
		/**
		* If `ctx` is given, the return type is actually `Map<unknown, unknown>`,
		* but TypeScript won't allow widening the signature of a child method.
		*/
		toJSON(_, ctx) {
			if (!ctx) return super.toJSON(_);
			const map = /* @__PURE__ */ new Map();
			if (ctx?.onCreate) ctx.onCreate(map);
			for (const pair of this.items) {
				let key, value;
				if (identity.isPair(pair)) {
					key = toJS.toJS(pair.key, "", ctx);
					value = toJS.toJS(pair.value, key, ctx);
				} else key = toJS.toJS(pair, "", ctx);
				if (map.has(key)) throw new Error("Ordered maps must not include duplicate keys");
				map.set(key, value);
			}
			return map;
		}
		static from(schema, iterable, ctx) {
			const pairs$1 = pairs.createPairs(schema, iterable, ctx);
			const omap = new this();
			omap.items = pairs$1.items;
			return omap;
		}
	};
	YAMLOMap.tag = "tag:yaml.org,2002:omap";
	const omap = {
		collection: "seq",
		identify: (value) => value instanceof Map,
		nodeClass: YAMLOMap,
		default: false,
		tag: "tag:yaml.org,2002:omap",
		resolve(seq, onError) {
			const pairs$1 = pairs.resolvePairs(seq, onError);
			const seenKeys = [];
			for (const { key } of pairs$1.items) if (identity.isScalar(key)) {
				if (seenKeys.includes(key.value)) onError(`Ordered maps must not include duplicate keys: ${key.value}`);
				else seenKeys.push(key.value);
			}
			return Object.assign(new YAMLOMap(), pairs$1);
		},
		createNode: (schema, iterable, ctx) => YAMLOMap.from(schema, iterable, ctx)
	};
	exports.YAMLOMap = YAMLOMap;
	exports.omap = omap;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/bool.js
var require_bool = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	function boolStringify({ value, source }, ctx) {
		if (source && (value ? trueTag : falseTag).test.test(source)) return source;
		return value ? ctx.options.trueStr : ctx.options.falseStr;
	}
	const trueTag = {
		identify: (value) => value === true,
		default: true,
		tag: "tag:yaml.org,2002:bool",
		test: /^(?:Y|y|[Yy]es|YES|[Tt]rue|TRUE|[Oo]n|ON)$/,
		resolve: () => new Scalar.Scalar(true),
		stringify: boolStringify
	};
	const falseTag = {
		identify: (value) => value === false,
		default: true,
		tag: "tag:yaml.org,2002:bool",
		test: /^(?:N|n|[Nn]o|NO|[Ff]alse|FALSE|[Oo]ff|OFF)$/,
		resolve: () => new Scalar.Scalar(false),
		stringify: boolStringify
	};
	exports.falseTag = falseTag;
	exports.trueTag = trueTag;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/float.js
var require_float = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	var stringifyNumber = require_stringifyNumber();
	const floatNaN = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		test: /^(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)$/,
		resolve: (str) => str.slice(-3).toLowerCase() === "nan" ? NaN : str[0] === "-" ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY,
		stringify: stringifyNumber.stringifyNumber
	};
	const floatExp = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		format: "EXP",
		test: /^[-+]?(?:[0-9][0-9_]*)?(?:\.[0-9_]*)?[eE][-+]?[0-9]+$/,
		resolve: (str) => parseFloat(str.replace(/_/g, "")),
		stringify(node) {
			const num = Number(node.value);
			return isFinite(num) ? num.toExponential() : stringifyNumber.stringifyNumber(node);
		}
	};
	exports.float = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		test: /^[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*$/,
		resolve(str) {
			const node = new Scalar.Scalar(parseFloat(str.replace(/_/g, "")));
			const dot = str.indexOf(".");
			if (dot !== -1) {
				const f = str.substring(dot + 1).replace(/_/g, "");
				if (f[f.length - 1] === "0") node.minFractionDigits = f.length;
			}
			return node;
		},
		stringify: stringifyNumber.stringifyNumber
	};
	exports.floatExp = floatExp;
	exports.floatNaN = floatNaN;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/int.js
var require_int = /* @__PURE__ */ __commonJSMin(((exports) => {
	var stringifyNumber = require_stringifyNumber();
	const intIdentify = (value) => typeof value === "bigint" || Number.isInteger(value);
	function intResolve(str, offset, radix, { intAsBigInt }) {
		const sign = str[0];
		if (sign === "-" || sign === "+") offset += 1;
		str = str.substring(offset).replace(/_/g, "");
		if (intAsBigInt) {
			switch (radix) {
				case 2:
					str = `0b${str}`;
					break;
				case 8:
					str = `0o${str}`;
					break;
				case 16: str = `0x${str}`;
			}
			const n = BigInt(str);
			return sign === "-" ? BigInt(-1) * n : n;
		}
		const n = parseInt(str, radix);
		return sign === "-" ? -1 * n : n;
	}
	function intStringify(node, radix, prefix) {
		const { value } = node;
		if (intIdentify(value)) {
			const str = value.toString(radix);
			return value < 0 ? "-" + prefix + str.substr(1) : prefix + str;
		}
		return stringifyNumber.stringifyNumber(node);
	}
	const intBin = {
		identify: intIdentify,
		default: true,
		tag: "tag:yaml.org,2002:int",
		format: "BIN",
		test: /^[-+]?0b[0-1_]+$/,
		resolve: (str, _onError, opt) => intResolve(str, 2, 2, opt),
		stringify: (node) => intStringify(node, 2, "0b")
	};
	const intOct = {
		identify: intIdentify,
		default: true,
		tag: "tag:yaml.org,2002:int",
		format: "OCT",
		test: /^[-+]?0[0-7_]+$/,
		resolve: (str, _onError, opt) => intResolve(str, 1, 8, opt),
		stringify: (node) => intStringify(node, 8, "0")
	};
	const int = {
		identify: intIdentify,
		default: true,
		tag: "tag:yaml.org,2002:int",
		test: /^[-+]?[0-9][0-9_]*$/,
		resolve: (str, _onError, opt) => intResolve(str, 0, 10, opt),
		stringify: stringifyNumber.stringifyNumber
	};
	const intHex = {
		identify: intIdentify,
		default: true,
		tag: "tag:yaml.org,2002:int",
		format: "HEX",
		test: /^[-+]?0x[0-9a-fA-F_]+$/,
		resolve: (str, _onError, opt) => intResolve(str, 2, 16, opt),
		stringify: (node) => intStringify(node, 16, "0x")
	};
	exports.int = int;
	exports.intBin = intBin;
	exports.intHex = intHex;
	exports.intOct = intOct;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/set.js
var require_set = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Pair = require_Pair();
	var YAMLMap = require_YAMLMap();
	var YAMLSet = class YAMLSet extends YAMLMap.YAMLMap {
		constructor(schema) {
			super(schema);
			this.tag = YAMLSet.tag;
		}
		add(key) {
			let pair;
			if (identity.isPair(key)) pair = key;
			else if (key && typeof key === "object" && "key" in key && "value" in key && key.value === null) pair = new Pair.Pair(key.key, null);
			else pair = new Pair.Pair(key, null);
			if (!YAMLMap.findPair(this.items, pair.key)) this.items.push(pair);
		}
		/**
		* If `keepPair` is `true`, returns the Pair matching `key`.
		* Otherwise, returns the value of that Pair's key.
		*/
		get(key, keepPair) {
			const pair = YAMLMap.findPair(this.items, key);
			return !keepPair && identity.isPair(pair) ? identity.isScalar(pair.key) ? pair.key.value : pair.key : pair;
		}
		set(key, value) {
			if (typeof value !== "boolean") throw new Error(`Expected boolean value for set(key, value) in a YAML set, not ${typeof value}`);
			const prev = YAMLMap.findPair(this.items, key);
			if (prev && !value) this.items.splice(this.items.indexOf(prev), 1);
			else if (!prev && value) this.items.push(new Pair.Pair(key));
		}
		toJSON(_, ctx) {
			return super.toJSON(_, ctx, Set);
		}
		toString(ctx, onComment, onChompKeep) {
			if (!ctx) return JSON.stringify(this);
			if (this.hasAllNullValues(true)) return super.toString(Object.assign({}, ctx, { allNullValues: true }), onComment, onChompKeep);
			else throw new Error("Set items must all have null values");
		}
		static from(schema, iterable, ctx) {
			const { replacer } = ctx;
			const set = new this(schema);
			if (iterable && Symbol.iterator in Object(iterable)) for (let value of iterable) {
				if (typeof replacer === "function") value = replacer.call(iterable, value, value);
				set.items.push(Pair.createPair(value, null, ctx));
			}
			return set;
		}
	};
	YAMLSet.tag = "tag:yaml.org,2002:set";
	const set = {
		collection: "map",
		identify: (value) => value instanceof Set,
		nodeClass: YAMLSet,
		default: false,
		tag: "tag:yaml.org,2002:set",
		createNode: (schema, iterable, ctx) => YAMLSet.from(schema, iterable, ctx),
		resolve(map, onError) {
			if (identity.isMap(map)) {
				if (map.hasAllNullValues(true)) return Object.assign(new YAMLSet(), map);
				else onError("Set items must all have null values");
			} else onError("Expected a mapping for this tag");
			return map;
		}
	};
	exports.YAMLSet = YAMLSet;
	exports.set = set;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/timestamp.js
var require_timestamp = /* @__PURE__ */ __commonJSMin(((exports) => {
	var stringifyNumber = require_stringifyNumber();
	/** Internal types handle bigint as number, because TS can't figure it out. */
	function parseSexagesimal(str, asBigInt) {
		const sign = str[0];
		const parts = sign === "-" || sign === "+" ? str.substring(1) : str;
		const num = (n) => asBigInt ? BigInt(n) : Number(n);
		const res = parts.replace(/_/g, "").split(":").reduce((res, p) => res * num(60) + num(p), num(0));
		return sign === "-" ? num(-1) * res : res;
	}
	/**
	* hhhh:mm:ss.sss
	*
	* Internal types handle bigint as number, because TS can't figure it out.
	*/
	function stringifySexagesimal(node) {
		let { value } = node;
		let num = (n) => n;
		if (typeof value === "bigint") num = (n) => BigInt(n);
		else if (isNaN(value) || !isFinite(value)) return stringifyNumber.stringifyNumber(node);
		let sign = "";
		if (value < 0) {
			sign = "-";
			value *= num(-1);
		}
		const _60 = num(60);
		const parts = [value % _60];
		if (value < 60) parts.unshift(0);
		else {
			value = (value - parts[0]) / _60;
			parts.unshift(value % _60);
			if (value >= 60) {
				value = (value - parts[0]) / _60;
				parts.unshift(value);
			}
		}
		return sign + parts.map((n) => String(n).padStart(2, "0")).join(":").replace(/000000\d*$/, "");
	}
	const intTime = {
		identify: (value) => typeof value === "bigint" || Number.isInteger(value),
		default: true,
		tag: "tag:yaml.org,2002:int",
		format: "TIME",
		test: /^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+$/,
		resolve: (str, _onError, { intAsBigInt }) => parseSexagesimal(str, intAsBigInt),
		stringify: stringifySexagesimal
	};
	const floatTime = {
		identify: (value) => typeof value === "number",
		default: true,
		tag: "tag:yaml.org,2002:float",
		format: "TIME",
		test: /^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*$/,
		resolve: (str) => parseSexagesimal(str, false),
		stringify: stringifySexagesimal
	};
	const timestamp = {
		identify: (value) => value instanceof Date,
		default: true,
		tag: "tag:yaml.org,2002:timestamp",
		test: RegExp("^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:(?:t|T|[ \\t]+)([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2}(\\.[0-9]+)?)(?:[ \\t]*(Z|[-+][012]?[0-9](?::[0-9]{2})?))?)?$"),
		resolve(str) {
			const match = str.match(timestamp.test);
			if (!match) throw new Error("!!timestamp expects a date, starting with yyyy-mm-dd");
			const [, year, month, day, hour, minute, second] = match.map(Number);
			const millisec = match[7] ? Number((match[7] + "00").substr(1, 3)) : 0;
			let date = Date.UTC(year, month - 1, day, hour || 0, minute || 0, second || 0, millisec);
			const tz = match[8];
			if (tz && tz !== "Z") {
				let d = parseSexagesimal(tz, false);
				if (Math.abs(d) < 30) d *= 60;
				date -= 6e4 * d;
			}
			return new Date(date);
		},
		stringify: ({ value }) => value?.toISOString().replace(/(T00:00:00)?\.000Z$/, "") ?? ""
	};
	exports.floatTime = floatTime;
	exports.intTime = intTime;
	exports.timestamp = timestamp;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/yaml-1.1/schema.js
var require_schema = /* @__PURE__ */ __commonJSMin(((exports) => {
	var map = require_map();
	var _null = require_null();
	var seq = require_seq();
	var string = require_string();
	var binary = require_binary();
	var bool = require_bool();
	var float = require_float();
	var int = require_int();
	var merge = require_merge();
	var omap = require_omap();
	var pairs = require_pairs();
	var set = require_set();
	var timestamp = require_timestamp();
	exports.schema = [
		map.map,
		seq.seq,
		string.string,
		_null.nullTag,
		bool.trueTag,
		bool.falseTag,
		int.intBin,
		int.intOct,
		int.int,
		int.intHex,
		float.floatNaN,
		float.floatExp,
		float.float,
		binary.binary,
		merge.merge,
		omap.omap,
		pairs.pairs,
		set.set,
		timestamp.intTime,
		timestamp.floatTime,
		timestamp.timestamp
	];
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/tags.js
var require_tags = /* @__PURE__ */ __commonJSMin(((exports) => {
	var map = require_map();
	var _null = require_null();
	var seq = require_seq();
	var string = require_string();
	var bool = require_bool$1();
	var float = require_float$1();
	var int = require_int$1();
	var schema = require_schema$2();
	var schema$1 = require_schema$1();
	var binary = require_binary();
	var merge = require_merge();
	var omap = require_omap();
	var pairs = require_pairs();
	var schema$2 = require_schema();
	var set = require_set();
	var timestamp = require_timestamp();
	const schemas = /* @__PURE__ */ new Map([
		["core", schema.schema],
		["failsafe", [
			map.map,
			seq.seq,
			string.string
		]],
		["json", schema$1.schema],
		["yaml11", schema$2.schema],
		["yaml-1.1", schema$2.schema]
	]);
	const tagsByName = {
		binary: binary.binary,
		bool: bool.boolTag,
		float: float.float,
		floatExp: float.floatExp,
		floatNaN: float.floatNaN,
		floatTime: timestamp.floatTime,
		int: int.int,
		intHex: int.intHex,
		intOct: int.intOct,
		intTime: timestamp.intTime,
		map: map.map,
		merge: merge.merge,
		null: _null.nullTag,
		omap: omap.omap,
		pairs: pairs.pairs,
		seq: seq.seq,
		set: set.set,
		timestamp: timestamp.timestamp
	};
	const coreKnownTags = {
		"tag:yaml.org,2002:binary": binary.binary,
		"tag:yaml.org,2002:merge": merge.merge,
		"tag:yaml.org,2002:omap": omap.omap,
		"tag:yaml.org,2002:pairs": pairs.pairs,
		"tag:yaml.org,2002:set": set.set,
		"tag:yaml.org,2002:timestamp": timestamp.timestamp
	};
	function getTags(customTags, schemaName, addMergeTag) {
		const schemaTags = schemas.get(schemaName);
		if (schemaTags && !customTags) return addMergeTag && !schemaTags.includes(merge.merge) ? schemaTags.concat(merge.merge) : schemaTags.slice();
		let tags = schemaTags;
		if (!tags) {
			if (Array.isArray(customTags)) tags = [];
			else {
				const keys = Array.from(schemas.keys()).filter((key) => key !== "yaml11").map((key) => JSON.stringify(key)).join(", ");
				throw new Error(`Unknown schema "${schemaName}"; use one of ${keys} or define customTags array`);
			}
		}
		if (Array.isArray(customTags)) for (const tag of customTags) tags = tags.concat(tag);
		else if (typeof customTags === "function") tags = customTags(tags.slice());
		if (addMergeTag) tags = tags.concat(merge.merge);
		return tags.reduce((tags, tag) => {
			const tagObj = typeof tag === "string" ? tagsByName[tag] : tag;
			if (!tagObj) {
				const tagName = JSON.stringify(tag);
				const keys = Object.keys(tagsByName).map((key) => JSON.stringify(key)).join(", ");
				throw new Error(`Unknown custom tag ${tagName}; use one of ${keys}`);
			}
			if (!tags.includes(tagObj)) tags.push(tagObj);
			return tags;
		}, []);
	}
	exports.coreKnownTags = coreKnownTags;
	exports.getTags = getTags;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/schema/Schema.js
var require_Schema = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var map = require_map();
	var seq = require_seq();
	var string = require_string();
	var tags = require_tags();
	const sortMapEntriesByKey = (a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
	exports.Schema = class Schema {
		constructor({ compat, customTags, merge, resolveKnownTags, schema, sortMapEntries, toStringDefaults }) {
			this.compat = Array.isArray(compat) ? tags.getTags(compat, "compat") : compat ? tags.getTags(null, compat) : null;
			this.name = typeof schema === "string" && schema || "core";
			this.knownTags = resolveKnownTags ? tags.coreKnownTags : {};
			this.tags = tags.getTags(customTags, this.name, merge);
			this.toStringOptions = toStringDefaults ?? null;
			Object.defineProperty(this, identity.MAP, { value: map.map });
			Object.defineProperty(this, identity.SCALAR, { value: string.string });
			Object.defineProperty(this, identity.SEQ, { value: seq.seq });
			this.sortMapEntries = typeof sortMapEntries === "function" ? sortMapEntries : sortMapEntries === true ? sortMapEntriesByKey : null;
		}
		clone() {
			const copy = Object.create(Schema.prototype, Object.getOwnPropertyDescriptors(this));
			copy.tags = this.tags.slice();
			return copy;
		}
	};
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/stringify/stringifyDocument.js
var require_stringifyDocument = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var stringify = require_stringify();
	var stringifyComment = require_stringifyComment();
	function stringifyDocument(doc, options) {
		const lines = [];
		let hasDirectives = options.directives === true;
		if (options.directives !== false && doc.directives) {
			const dir = doc.directives.toString(doc);
			if (dir) {
				lines.push(dir);
				hasDirectives = true;
			} else if (doc.directives.docStart) hasDirectives = true;
		}
		if (hasDirectives) lines.push("---");
		const ctx = stringify.createStringifyContext(doc, options);
		const { commentString } = ctx.options;
		if (doc.commentBefore) {
			if (lines.length !== 1) lines.unshift("");
			const cs = commentString(doc.commentBefore);
			lines.unshift(stringifyComment.indentComment(cs, ""));
		}
		let chompKeep = false;
		let contentComment = null;
		if (doc.contents) {
			if (identity.isNode(doc.contents)) {
				if (doc.contents.spaceBefore && hasDirectives) lines.push("");
				if (doc.contents.commentBefore) {
					const cs = commentString(doc.contents.commentBefore);
					lines.push(stringifyComment.indentComment(cs, ""));
				}
				ctx.forceBlockIndent = !!doc.comment;
				contentComment = doc.contents.comment;
			}
			const onChompKeep = contentComment ? void 0 : () => chompKeep = true;
			let body = stringify.stringify(doc.contents, ctx, () => contentComment = null, onChompKeep);
			if (contentComment) body += stringifyComment.lineComment(body, "", commentString(contentComment));
			if ((body[0] === "|" || body[0] === ">") && lines[lines.length - 1] === "---") lines[lines.length - 1] = `--- ${body}`;
			else lines.push(body);
		} else lines.push(stringify.stringify(doc.contents, ctx));
		if (doc.directives?.docEnd) {
			if (doc.comment) {
				const cs = commentString(doc.comment);
				if (cs.includes("\n")) {
					lines.push("...");
					lines.push(stringifyComment.indentComment(cs, ""));
				} else lines.push(`... ${cs}`);
			} else lines.push("...");
		} else {
			let dc = doc.comment;
			if (dc && chompKeep) dc = dc.replace(/^\n+/, "");
			if (dc) {
				if ((!chompKeep || contentComment) && lines[lines.length - 1] !== "") lines.push("");
				lines.push(stringifyComment.indentComment(commentString(dc), ""));
			}
		}
		return lines.join("\n") + "\n";
	}
	exports.stringifyDocument = stringifyDocument;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/doc/Document.js
var require_Document = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Alias = require_Alias();
	var Collection = require_Collection();
	var identity = require_identity();
	var Pair = require_Pair();
	var toJS = require_toJS();
	var Schema = require_Schema();
	var stringifyDocument = require_stringifyDocument();
	var anchors = require_anchors();
	var applyReviver = require_applyReviver();
	var createNode = require_createNode();
	var directives = require_directives();
	var Document = class Document {
		constructor(value, replacer, options) {
			/** A comment before this Document */
			this.commentBefore = null;
			/** A comment immediately after this Document */
			this.comment = null;
			/** Errors encountered during parsing. */
			this.errors = [];
			/** Warnings encountered during parsing. */
			this.warnings = [];
			Object.defineProperty(this, identity.NODE_TYPE, { value: identity.DOC });
			let _replacer = null;
			if (typeof replacer === "function" || Array.isArray(replacer)) _replacer = replacer;
			else if (options === void 0 && replacer) {
				options = replacer;
				replacer = void 0;
			}
			const opt = Object.assign({
				intAsBigInt: false,
				keepSourceTokens: false,
				logLevel: "warn",
				prettyErrors: true,
				strict: true,
				stringKeys: false,
				uniqueKeys: true,
				version: "1.2"
			}, options);
			this.options = opt;
			let { version } = opt;
			if (options?._directives) {
				this.directives = options._directives.atDocument();
				if (this.directives.yaml.explicit) version = this.directives.yaml.version;
			} else this.directives = new directives.Directives({ version });
			this.setSchema(version, options);
			this.contents = value === void 0 ? null : this.createNode(value, _replacer, options);
		}
		/**
		* Create a deep copy of this Document and its contents.
		*
		* Custom Node values that inherit from `Object` still refer to their original instances.
		*/
		clone() {
			const copy = Object.create(Document.prototype, { [identity.NODE_TYPE]: { value: identity.DOC } });
			copy.commentBefore = this.commentBefore;
			copy.comment = this.comment;
			copy.errors = this.errors.slice();
			copy.warnings = this.warnings.slice();
			copy.options = Object.assign({}, this.options);
			if (this.directives) copy.directives = this.directives.clone();
			copy.schema = this.schema.clone();
			copy.contents = identity.isNode(this.contents) ? this.contents.clone(copy.schema) : this.contents;
			if (this.range) copy.range = this.range.slice();
			return copy;
		}
		/** Adds a value to the document. */
		add(value) {
			if (assertCollection(this.contents)) this.contents.add(value);
		}
		/** Adds a value to the document. */
		addIn(path, value) {
			if (assertCollection(this.contents)) this.contents.addIn(path, value);
		}
		/**
		* Create a new `Alias` node, ensuring that the target `node` has the required anchor.
		*
		* If `node` already has an anchor, `name` is ignored.
		* Otherwise, the `node.anchor` value will be set to `name`,
		* or if an anchor with that name is already present in the document,
		* `name` will be used as a prefix for a new unique anchor.
		* If `name` is undefined, the generated anchor will use 'a' as a prefix.
		*/
		createAlias(node, name) {
			if (!node.anchor) {
				const prev = anchors.anchorNames(this);
				node.anchor = !name || prev.has(name) ? anchors.findNewAnchor(name || "a", prev) : name;
			}
			return new Alias.Alias(node.anchor);
		}
		createNode(value, replacer, options) {
			let _replacer = void 0;
			if (typeof replacer === "function") {
				value = replacer.call({ "": value }, "", value);
				_replacer = replacer;
			} else if (Array.isArray(replacer)) {
				const keyToStr = (v) => typeof v === "number" || v instanceof String || v instanceof Number;
				const asStr = replacer.filter(keyToStr).map(String);
				if (asStr.length > 0) replacer = replacer.concat(asStr);
				_replacer = replacer;
			} else if (options === void 0 && replacer) {
				options = replacer;
				replacer = void 0;
			}
			const { aliasDuplicateObjects, anchorPrefix, flow, keepUndefined, onTagObj, tag } = options ?? {};
			const { onAnchor, setAnchors, sourceObjects } = anchors.createNodeAnchors(this, anchorPrefix || "a");
			const ctx = {
				aliasDuplicateObjects: aliasDuplicateObjects ?? true,
				keepUndefined: keepUndefined ?? false,
				onAnchor,
				onTagObj,
				replacer: _replacer,
				schema: this.schema,
				sourceObjects
			};
			const node = createNode.createNode(value, tag, ctx);
			if (flow && identity.isCollection(node)) node.flow = true;
			setAnchors();
			return node;
		}
		/**
		* Convert a key and a value into a `Pair` using the current schema,
		* recursively wrapping all values as `Scalar` or `Collection` nodes.
		*/
		createPair(key, value, options = {}) {
			const k = this.createNode(key, null, options);
			const v = this.createNode(value, null, options);
			return new Pair.Pair(k, v);
		}
		/**
		* Removes a value from the document.
		* @returns `true` if the item was found and removed.
		*/
		delete(key) {
			return assertCollection(this.contents) ? this.contents.delete(key) : false;
		}
		/**
		* Removes a value from the document.
		* @returns `true` if the item was found and removed.
		*/
		deleteIn(path) {
			if (Collection.isEmptyPath(path)) {
				if (this.contents == null) return false;
				this.contents = null;
				return true;
			}
			return assertCollection(this.contents) ? this.contents.deleteIn(path) : false;
		}
		/**
		* Returns item at `key`, or `undefined` if not found. By default unwraps
		* scalar values from their surrounding node; to disable set `keepScalar` to
		* `true` (collections are always returned intact).
		*/
		get(key, keepScalar) {
			return identity.isCollection(this.contents) ? this.contents.get(key, keepScalar) : void 0;
		}
		/**
		* Returns item at `path`, or `undefined` if not found. By default unwraps
		* scalar values from their surrounding node; to disable set `keepScalar` to
		* `true` (collections are always returned intact).
		*/
		getIn(path, keepScalar) {
			if (Collection.isEmptyPath(path)) return !keepScalar && identity.isScalar(this.contents) ? this.contents.value : this.contents;
			return identity.isCollection(this.contents) ? this.contents.getIn(path, keepScalar) : void 0;
		}
		/**
		* Checks if the document includes a value with the key `key`.
		*/
		has(key) {
			return identity.isCollection(this.contents) ? this.contents.has(key) : false;
		}
		/**
		* Checks if the document includes a value at `path`.
		*/
		hasIn(path) {
			if (Collection.isEmptyPath(path)) return this.contents !== void 0;
			return identity.isCollection(this.contents) ? this.contents.hasIn(path) : false;
		}
		/**
		* Sets a value in this document. For `!!set`, `value` needs to be a
		* boolean to add/remove the item from the set.
		*/
		set(key, value) {
			if (this.contents == null) this.contents = Collection.collectionFromPath(this.schema, [key], value);
			else if (assertCollection(this.contents)) this.contents.set(key, value);
		}
		/**
		* Sets a value in this document. For `!!set`, `value` needs to be a
		* boolean to add/remove the item from the set.
		*/
		setIn(path, value) {
			if (Collection.isEmptyPath(path)) this.contents = value;
			else if (this.contents == null) this.contents = Collection.collectionFromPath(this.schema, Array.from(path), value);
			else if (assertCollection(this.contents)) this.contents.setIn(path, value);
		}
		/**
		* Change the YAML version and schema used by the document.
		* A `null` version disables support for directives, explicit tags, anchors, and aliases.
		* It also requires the `schema` option to be given as a `Schema` instance value.
		*
		* Overrides all previously set schema options.
		*/
		setSchema(version, options = {}) {
			if (typeof version === "number") version = String(version);
			let opt;
			switch (version) {
				case "1.1":
					if (this.directives) this.directives.yaml.version = "1.1";
					else this.directives = new directives.Directives({ version: "1.1" });
					opt = {
						resolveKnownTags: false,
						schema: "yaml-1.1"
					};
					break;
				case "1.2":
				case "next":
					if (this.directives) this.directives.yaml.version = version;
					else this.directives = new directives.Directives({ version });
					opt = {
						resolveKnownTags: true,
						schema: "core"
					};
					break;
				case null:
					if (this.directives) delete this.directives;
					opt = null;
					break;
				default: {
					const sv = JSON.stringify(version);
					throw new Error(`Expected '1.1', '1.2' or null as first argument, but found: ${sv}`);
				}
			}
			if (options.schema instanceof Object) this.schema = options.schema;
			else if (opt) this.schema = new Schema.Schema(Object.assign(opt, options));
			else throw new Error(`With a null YAML version, the { schema: Schema } option is required`);
		}
		toJS({ json, jsonArg, mapAsMap, maxAliasCount, onAnchor, reviver } = {}) {
			const ctx = {
				anchors: /* @__PURE__ */ new Map(),
				doc: this,
				keep: !json,
				mapAsMap: mapAsMap === true,
				mapKeyWarned: false,
				maxAliasCount: typeof maxAliasCount === "number" ? maxAliasCount : 100
			};
			const res = toJS.toJS(this.contents, jsonArg ?? "", ctx);
			if (typeof onAnchor === "function") for (const { count, res } of ctx.anchors.values()) onAnchor(res, count);
			return typeof reviver === "function" ? applyReviver.applyReviver(reviver, { "": res }, "", res) : res;
		}
		/**
		* A JSON representation of the document `contents`.
		*
		* @param jsonArg Used by `JSON.stringify` to indicate the array index or
		*   property name.
		*/
		toJSON(jsonArg, onAnchor) {
			return this.toJS({
				json: true,
				jsonArg,
				mapAsMap: false,
				onAnchor
			});
		}
		/** A YAML representation of the document. */
		toString(options = {}) {
			if (this.errors.length > 0) throw new Error("Document with errors cannot be stringified");
			if ("indent" in options && (!Number.isInteger(options.indent) || Number(options.indent) <= 0)) {
				const s = JSON.stringify(options.indent);
				throw new Error(`"indent" option must be a positive integer, not ${s}`);
			}
			return stringifyDocument.stringifyDocument(this, options);
		}
	};
	function assertCollection(contents) {
		if (identity.isCollection(contents)) return true;
		throw new Error("Expected a YAML collection as document contents");
	}
	exports.Document = Document;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/errors.js
var require_errors = /* @__PURE__ */ __commonJSMin(((exports) => {
	var YAMLError = class extends Error {
		constructor(name, pos, code, message) {
			super();
			this.name = name;
			this.code = code;
			this.message = message;
			this.pos = pos;
		}
	};
	var YAMLParseError = class extends YAMLError {
		constructor(pos, code, message) {
			super("YAMLParseError", pos, code, message);
		}
	};
	var YAMLWarning = class extends YAMLError {
		constructor(pos, code, message) {
			super("YAMLWarning", pos, code, message);
		}
	};
	const prettifyError = (src, lc) => (error) => {
		if (error.pos[0] === -1) return;
		error.linePos = error.pos.map((pos) => lc.linePos(pos));
		const { line, col } = error.linePos[0];
		error.message += ` at line ${line}, column ${col}`;
		let ci = col - 1;
		let lineStr = src.substring(lc.lineStarts[line - 1], lc.lineStarts[line]).replace(/[\n\r]+$/, "");
		if (ci >= 60 && lineStr.length > 80) {
			const trimStart = Math.min(ci - 39, lineStr.length - 79);
			lineStr = "…" + lineStr.substring(trimStart);
			ci -= trimStart - 1;
		}
		if (lineStr.length > 80) lineStr = lineStr.substring(0, 79) + "…";
		if (line > 1 && /^ *$/.test(lineStr.substring(0, ci))) {
			let prev = src.substring(lc.lineStarts[line - 2], lc.lineStarts[line - 1]);
			if (prev.length > 80) prev = prev.substring(0, 79) + "…\n";
			lineStr = prev + lineStr;
		}
		if (/[^ ]/.test(lineStr)) {
			let count = 1;
			const end = error.linePos[1];
			if (end?.line === line && end.col > col) count = Math.max(1, Math.min(end.col - col, 80 - ci));
			const pointer = " ".repeat(ci) + "^".repeat(count);
			error.message += `:\n\n${lineStr}\n${pointer}\n`;
		}
	};
	exports.YAMLError = YAMLError;
	exports.YAMLParseError = YAMLParseError;
	exports.YAMLWarning = YAMLWarning;
	exports.prettifyError = prettifyError;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-props.js
var require_resolve_props = /* @__PURE__ */ __commonJSMin(((exports) => {
	function resolveProps(tokens, { flow, indicator, next, offset, onError, parentIndent, startOnNewline }) {
		let spaceBefore = false;
		let atNewline = startOnNewline;
		let hasSpace = startOnNewline;
		let comment = "";
		let commentSep = "";
		let hasNewline = false;
		let reqSpace = false;
		let tab = null;
		let anchor = null;
		let tag = null;
		let newlineAfterProp = null;
		let comma = null;
		let found = null;
		let start = null;
		for (const token of tokens) {
			if (reqSpace) {
				if (token.type !== "space" && token.type !== "newline" && token.type !== "comma") onError(token.offset, "MISSING_CHAR", "Tags and anchors must be separated from the next token by white space");
				reqSpace = false;
			}
			if (tab) {
				if (atNewline && token.type !== "comment" && token.type !== "newline") onError(tab, "TAB_AS_INDENT", "Tabs are not allowed as indentation");
				tab = null;
			}
			switch (token.type) {
				case "space":
					if (!flow && (indicator !== "doc-start" || next?.type !== "flow-collection") && token.source.includes("	")) tab = token;
					hasSpace = true;
					break;
				case "comment": {
					if (!hasSpace) onError(token, "MISSING_CHAR", "Comments must be separated from other tokens by white space characters");
					const cb = token.source.substring(1) || " ";
					if (!comment) comment = cb;
					else comment += commentSep + cb;
					commentSep = "";
					atNewline = false;
					break;
				}
				case "newline":
					if (atNewline) {
						if (comment) comment += token.source;
						else if (!found || indicator !== "seq-item-ind") spaceBefore = true;
					} else commentSep += token.source;
					atNewline = true;
					hasNewline = true;
					if (anchor || tag) newlineAfterProp = token;
					hasSpace = true;
					break;
				case "anchor":
					if (anchor) onError(token, "MULTIPLE_ANCHORS", "A node can have at most one anchor");
					if (token.source.endsWith(":")) onError(token.offset + token.source.length - 1, "BAD_ALIAS", "Anchor ending in : is ambiguous", true);
					anchor = token;
					start ?? (start = token.offset);
					atNewline = false;
					hasSpace = false;
					reqSpace = true;
					break;
				case "tag":
					if (tag) onError(token, "MULTIPLE_TAGS", "A node can have at most one tag");
					tag = token;
					start ?? (start = token.offset);
					atNewline = false;
					hasSpace = false;
					reqSpace = true;
					break;
				case indicator:
					if (anchor || tag) onError(token, "BAD_PROP_ORDER", `Anchors and tags must be after the ${token.source} indicator`);
					if (found) onError(token, "UNEXPECTED_TOKEN", `Unexpected ${token.source} in ${flow ?? "collection"}`);
					found = token;
					atNewline = indicator === "seq-item-ind" || indicator === "explicit-key-ind";
					hasSpace = false;
					break;
				case "comma": if (flow) {
					if (comma) onError(token, "UNEXPECTED_TOKEN", `Unexpected , in ${flow}`);
					comma = token;
					atNewline = false;
					hasSpace = false;
					break;
				}
				default:
					onError(token, "UNEXPECTED_TOKEN", `Unexpected ${token.type} token`);
					atNewline = false;
					hasSpace = false;
			}
		}
		const last = tokens[tokens.length - 1];
		const end = last ? last.offset + last.source.length : offset;
		if (reqSpace && next && next.type !== "space" && next.type !== "newline" && next.type !== "comma" && (next.type !== "scalar" || next.source !== "")) onError(next.offset, "MISSING_CHAR", "Tags and anchors must be separated from the next token by white space");
		if (tab && (atNewline && tab.indent <= parentIndent || next?.type === "block-map" || next?.type === "block-seq")) onError(tab, "TAB_AS_INDENT", "Tabs are not allowed as indentation");
		return {
			comma,
			found,
			spaceBefore,
			comment,
			hasNewline,
			anchor,
			tag,
			newlineAfterProp,
			end,
			start: start ?? end
		};
	}
	exports.resolveProps = resolveProps;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/util-contains-newline.js
var require_util_contains_newline = /* @__PURE__ */ __commonJSMin(((exports) => {
	function containsNewline(key) {
		if (!key) return null;
		switch (key.type) {
			case "alias":
			case "scalar":
			case "double-quoted-scalar":
			case "single-quoted-scalar":
				if (key.source.includes("\n")) return true;
				if (key.end) {
					for (const st of key.end) if (st.type === "newline") return true;
				}
				return false;
			case "flow-collection":
				for (const it of key.items) {
					for (const st of it.start) if (st.type === "newline") return true;
					if (it.sep) {
						for (const st of it.sep) if (st.type === "newline") return true;
					}
					if (containsNewline(it.key) || containsNewline(it.value)) return true;
				}
				return false;
			default: return true;
		}
	}
	exports.containsNewline = containsNewline;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/util-flow-indent-check.js
var require_util_flow_indent_check = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilContainsNewline = require_util_contains_newline();
	function flowIndentCheck(indent, fc, onError) {
		if (fc?.type === "flow-collection") {
			const end = fc.end[0];
			if (end.indent === indent && (end.source === "]" || end.source === "}") && utilContainsNewline.containsNewline(fc)) onError(end, "BAD_INDENT", "Flow end indicator should be more indented than parent", true);
		}
	}
	exports.flowIndentCheck = flowIndentCheck;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/util-map-includes.js
var require_util_map_includes = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	function mapIncludes(ctx, items, search) {
		const { uniqueKeys } = ctx.options;
		if (uniqueKeys === false) return false;
		const isEqual = typeof uniqueKeys === "function" ? uniqueKeys : (a, b) => a === b || identity.isScalar(a) && identity.isScalar(b) && a.value === b.value;
		return items.some((pair) => isEqual(pair.key, search));
	}
	exports.mapIncludes = mapIncludes;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-block-map.js
var require_resolve_block_map = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Pair = require_Pair();
	var YAMLMap = require_YAMLMap();
	var resolveProps = require_resolve_props();
	var utilContainsNewline = require_util_contains_newline();
	var utilFlowIndentCheck = require_util_flow_indent_check();
	var utilMapIncludes = require_util_map_includes();
	const startColMsg = "All mapping items must start at the same column";
	function resolveBlockMap({ composeNode, composeEmptyNode }, ctx, bm, onError, tag) {
		const map = new ((tag?.nodeClass) ?? YAMLMap.YAMLMap)(ctx.schema);
		if (ctx.atRoot) ctx.atRoot = false;
		let offset = bm.offset;
		let commentEnd = null;
		for (const collItem of bm.items) {
			const { start, key, sep, value } = collItem;
			const keyProps = resolveProps.resolveProps(start, {
				indicator: "explicit-key-ind",
				next: key ?? sep?.[0],
				offset,
				onError,
				parentIndent: bm.indent,
				startOnNewline: true
			});
			const implicitKey = !keyProps.found;
			if (implicitKey) {
				if (key) {
					if (key.type === "block-seq") onError(offset, "BLOCK_AS_IMPLICIT_KEY", "A block sequence may not be used as an implicit map key");
					else if ("indent" in key && key.indent !== bm.indent) onError(offset, "BAD_INDENT", startColMsg);
				}
				if (!keyProps.anchor && !keyProps.tag && !sep) {
					commentEnd = keyProps.end;
					if (keyProps.comment) {
						if (map.comment) map.comment += "\n" + keyProps.comment;
						else map.comment = keyProps.comment;
					}
					continue;
				}
				if (keyProps.newlineAfterProp || utilContainsNewline.containsNewline(key)) onError(key ?? start[start.length - 1], "MULTILINE_IMPLICIT_KEY", "Implicit keys need to be on a single line");
			} else if (keyProps.found?.indent !== bm.indent) onError(offset, "BAD_INDENT", startColMsg);
			ctx.atKey = true;
			const keyStart = keyProps.end;
			const keyNode = key ? composeNode(ctx, key, keyProps, onError) : composeEmptyNode(ctx, keyStart, start, null, keyProps, onError);
			if (ctx.schema.compat) utilFlowIndentCheck.flowIndentCheck(bm.indent, key, onError);
			ctx.atKey = false;
			if (utilMapIncludes.mapIncludes(ctx, map.items, keyNode)) onError(keyStart, "DUPLICATE_KEY", "Map keys must be unique");
			const valueProps = resolveProps.resolveProps(sep ?? [], {
				indicator: "map-value-ind",
				next: value,
				offset: keyNode.range[2],
				onError,
				parentIndent: bm.indent,
				startOnNewline: !key || key.type === "block-scalar"
			});
			offset = valueProps.end;
			if (valueProps.found) {
				if (implicitKey) {
					if (value?.type === "block-map" && !valueProps.hasNewline) onError(offset, "BLOCK_AS_IMPLICIT_KEY", "Nested mappings are not allowed in compact mappings");
					if (ctx.options.strict && keyProps.start < valueProps.found.offset - 1024) onError(keyNode.range, "KEY_OVER_1024_CHARS", "The : indicator must be at most 1024 chars after the start of an implicit block mapping key");
				}
				const valueNode = value ? composeNode(ctx, value, valueProps, onError) : composeEmptyNode(ctx, offset, sep, null, valueProps, onError);
				if (ctx.schema.compat) utilFlowIndentCheck.flowIndentCheck(bm.indent, value, onError);
				offset = valueNode.range[2];
				const pair = new Pair.Pair(keyNode, valueNode);
				if (ctx.options.keepSourceTokens) pair.srcToken = collItem;
				map.items.push(pair);
			} else {
				if (implicitKey) onError(keyNode.range, "MISSING_CHAR", "Implicit map keys need to be followed by map values");
				if (valueProps.comment) {
					if (keyNode.comment) keyNode.comment += "\n" + valueProps.comment;
					else keyNode.comment = valueProps.comment;
				}
				const pair = new Pair.Pair(keyNode);
				if (ctx.options.keepSourceTokens) pair.srcToken = collItem;
				map.items.push(pair);
			}
		}
		if (commentEnd && commentEnd < offset) onError(commentEnd, "IMPOSSIBLE", "Map comment with trailing content");
		map.range = [
			bm.offset,
			offset,
			commentEnd ?? offset
		];
		return map;
	}
	exports.resolveBlockMap = resolveBlockMap;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-block-seq.js
var require_resolve_block_seq = /* @__PURE__ */ __commonJSMin(((exports) => {
	var YAMLSeq = require_YAMLSeq();
	var resolveProps = require_resolve_props();
	var utilFlowIndentCheck = require_util_flow_indent_check();
	function resolveBlockSeq({ composeNode, composeEmptyNode }, ctx, bs, onError, tag) {
		const seq = new ((tag?.nodeClass) ?? YAMLSeq.YAMLSeq)(ctx.schema);
		if (ctx.atRoot) ctx.atRoot = false;
		if (ctx.atKey) ctx.atKey = false;
		let offset = bs.offset;
		let commentEnd = null;
		for (const { start, value } of bs.items) {
			const props = resolveProps.resolveProps(start, {
				indicator: "seq-item-ind",
				next: value,
				offset,
				onError,
				parentIndent: bs.indent,
				startOnNewline: true
			});
			if (!props.found) {
				if (props.anchor || props.tag || value) {
					if (value?.type === "block-seq") onError(props.end, "BAD_INDENT", "All sequence items must start at the same column");
					else onError(offset, "MISSING_CHAR", "Sequence item without - indicator");
				} else {
					commentEnd = props.end;
					if (props.comment) seq.comment = props.comment;
					continue;
				}
			}
			const node = value ? composeNode(ctx, value, props, onError) : composeEmptyNode(ctx, props.end, start, null, props, onError);
			if (ctx.schema.compat) utilFlowIndentCheck.flowIndentCheck(bs.indent, value, onError);
			offset = node.range[2];
			seq.items.push(node);
		}
		seq.range = [
			bs.offset,
			offset,
			commentEnd ?? offset
		];
		return seq;
	}
	exports.resolveBlockSeq = resolveBlockSeq;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-end.js
var require_resolve_end = /* @__PURE__ */ __commonJSMin(((exports) => {
	function resolveEnd(end, offset, reqSpace, onError) {
		let comment = "";
		if (end) {
			let hasSpace = false;
			let sep = "";
			for (const token of end) {
				const { source, type } = token;
				switch (type) {
					case "space":
						hasSpace = true;
						break;
					case "comment": {
						if (reqSpace && !hasSpace) onError(token, "MISSING_CHAR", "Comments must be separated from other tokens by white space characters");
						const cb = source.substring(1) || " ";
						if (!comment) comment = cb;
						else comment += sep + cb;
						sep = "";
						break;
					}
					case "newline":
						if (comment) sep += source;
						hasSpace = true;
						break;
					default: onError(token, "UNEXPECTED_TOKEN", `Unexpected ${type} at node end`);
				}
				offset += source.length;
			}
		}
		return {
			comment,
			offset
		};
	}
	exports.resolveEnd = resolveEnd;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-flow-collection.js
var require_resolve_flow_collection = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Pair = require_Pair();
	var YAMLMap = require_YAMLMap();
	var YAMLSeq = require_YAMLSeq();
	var resolveEnd = require_resolve_end();
	var resolveProps = require_resolve_props();
	var utilContainsNewline = require_util_contains_newline();
	var utilMapIncludes = require_util_map_includes();
	const blockMsg = "Block collections are not allowed within flow collections";
	const isBlock = (token) => token && (token.type === "block-map" || token.type === "block-seq");
	function resolveFlowCollection({ composeNode, composeEmptyNode }, ctx, fc, onError, tag) {
		const isMap = fc.start.source === "{";
		const fcName = isMap ? "flow map" : "flow sequence";
		const coll = new ((tag?.nodeClass) ?? (isMap ? YAMLMap.YAMLMap : YAMLSeq.YAMLSeq))(ctx.schema);
		coll.flow = true;
		const atRoot = ctx.atRoot;
		if (atRoot) ctx.atRoot = false;
		if (ctx.atKey) ctx.atKey = false;
		let offset = fc.offset + fc.start.source.length;
		for (let i = 0; i < fc.items.length; ++i) {
			const collItem = fc.items[i];
			const { start, key, sep, value } = collItem;
			const props = resolveProps.resolveProps(start, {
				flow: fcName,
				indicator: "explicit-key-ind",
				next: key ?? sep?.[0],
				offset,
				onError,
				parentIndent: fc.indent,
				startOnNewline: false
			});
			if (!props.found) {
				if (!props.anchor && !props.tag && !sep && !value) {
					if (i === 0 && props.comma) onError(props.comma, "UNEXPECTED_TOKEN", `Unexpected , in ${fcName}`);
					else if (i < fc.items.length - 1) onError(props.start, "UNEXPECTED_TOKEN", `Unexpected empty item in ${fcName}`);
					if (props.comment) {
						if (coll.comment) coll.comment += "\n" + props.comment;
						else coll.comment = props.comment;
					}
					offset = props.end;
					continue;
				}
				if (!isMap && ctx.options.strict && utilContainsNewline.containsNewline(key)) onError(key, "MULTILINE_IMPLICIT_KEY", "Implicit keys of flow sequence pairs need to be on a single line");
			}
			if (i === 0) {
				if (props.comma) onError(props.comma, "UNEXPECTED_TOKEN", `Unexpected , in ${fcName}`);
			} else {
				if (!props.comma) onError(props.start, "MISSING_CHAR", `Missing , between ${fcName} items`);
				if (props.comment) {
					let prevItemComment = "";
					loop: for (const st of start) switch (st.type) {
						case "comma":
						case "space": break;
						case "comment":
							prevItemComment = st.source.substring(1);
							break loop;
						default: break loop;
					}
					if (prevItemComment) {
						let prev = coll.items[coll.items.length - 1];
						if (identity.isPair(prev)) prev = prev.value ?? prev.key;
						if (prev.comment) prev.comment += "\n" + prevItemComment;
						else prev.comment = prevItemComment;
						props.comment = props.comment.substring(prevItemComment.length + 1);
					}
				}
			}
			if (!isMap && !sep && !props.found) {
				const valueNode = value ? composeNode(ctx, value, props, onError) : composeEmptyNode(ctx, props.end, sep, null, props, onError);
				coll.items.push(valueNode);
				offset = valueNode.range[2];
				if (isBlock(value)) onError(valueNode.range, "BLOCK_IN_FLOW", blockMsg);
			} else {
				ctx.atKey = true;
				const keyStart = props.end;
				const keyNode = key ? composeNode(ctx, key, props, onError) : composeEmptyNode(ctx, keyStart, start, null, props, onError);
				if (isBlock(key)) onError(keyNode.range, "BLOCK_IN_FLOW", blockMsg);
				ctx.atKey = false;
				const valueProps = resolveProps.resolveProps(sep ?? [], {
					flow: fcName,
					indicator: "map-value-ind",
					next: value,
					offset: keyNode.range[2],
					onError,
					parentIndent: fc.indent,
					startOnNewline: false
				});
				if (valueProps.found) {
					if (!isMap && !props.found && ctx.options.strict) {
						if (sep) for (const st of sep) {
							if (st === valueProps.found) break;
							if (st.type === "newline") {
								onError(st, "MULTILINE_IMPLICIT_KEY", "Implicit keys of flow sequence pairs need to be on a single line");
								break;
							}
						}
						if (props.start < valueProps.found.offset - 1024) onError(valueProps.found, "KEY_OVER_1024_CHARS", "The : indicator must be at most 1024 chars after the start of an implicit flow sequence key");
					}
				} else if (value) {
					if ("source" in value && value.source?.[0] === ":") onError(value, "MISSING_CHAR", `Missing space after : in ${fcName}`);
					else onError(valueProps.start, "MISSING_CHAR", `Missing , or : between ${fcName} items`);
				}
				const valueNode = value ? composeNode(ctx, value, valueProps, onError) : valueProps.found ? composeEmptyNode(ctx, valueProps.end, sep, null, valueProps, onError) : null;
				if (valueNode) {
					if (isBlock(value)) onError(valueNode.range, "BLOCK_IN_FLOW", blockMsg);
				} else if (valueProps.comment) {
					if (keyNode.comment) keyNode.comment += "\n" + valueProps.comment;
					else keyNode.comment = valueProps.comment;
				}
				const pair = new Pair.Pair(keyNode, valueNode);
				if (ctx.options.keepSourceTokens) pair.srcToken = collItem;
				if (isMap) {
					const map = coll;
					if (utilMapIncludes.mapIncludes(ctx, map.items, keyNode)) onError(keyStart, "DUPLICATE_KEY", "Map keys must be unique");
					map.items.push(pair);
				} else {
					const map = new YAMLMap.YAMLMap(ctx.schema);
					map.flow = true;
					map.items.push(pair);
					const endRange = (valueNode ?? keyNode).range;
					map.range = [
						keyNode.range[0],
						endRange[1],
						endRange[2]
					];
					coll.items.push(map);
				}
				offset = valueNode ? valueNode.range[2] : valueProps.end;
			}
		}
		const expectedEnd = isMap ? "}" : "]";
		const [ce, ...ee] = fc.end;
		let cePos = offset;
		if (ce?.source === expectedEnd) cePos = ce.offset + ce.source.length;
		else {
			const name = fcName[0].toUpperCase() + fcName.substring(1);
			const msg = atRoot ? `${name} must end with a ${expectedEnd}` : `${name} in block collection must be sufficiently indented and end with a ${expectedEnd}`;
			onError(offset, atRoot ? "MISSING_CHAR" : "BAD_INDENT", msg);
			if (ce && ce.source.length !== 1) ee.unshift(ce);
		}
		if (ee.length > 0) {
			const end = resolveEnd.resolveEnd(ee, cePos, ctx.options.strict, onError);
			if (end.comment) {
				if (coll.comment) coll.comment += "\n" + end.comment;
				else coll.comment = end.comment;
			}
			coll.range = [
				fc.offset,
				cePos,
				end.offset
			];
		} else coll.range = [
			fc.offset,
			cePos,
			cePos
		];
		return coll;
	}
	exports.resolveFlowCollection = resolveFlowCollection;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/compose-collection.js
var require_compose_collection = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Scalar = require_Scalar();
	var YAMLMap = require_YAMLMap();
	var YAMLSeq = require_YAMLSeq();
	var resolveBlockMap = require_resolve_block_map();
	var resolveBlockSeq = require_resolve_block_seq();
	var resolveFlowCollection = require_resolve_flow_collection();
	function resolveCollection(CN, ctx, token, onError, tagName, tag) {
		const coll = token.type === "block-map" ? resolveBlockMap.resolveBlockMap(CN, ctx, token, onError, tag) : token.type === "block-seq" ? resolveBlockSeq.resolveBlockSeq(CN, ctx, token, onError, tag) : resolveFlowCollection.resolveFlowCollection(CN, ctx, token, onError, tag);
		const Coll = coll.constructor;
		if (tagName === "!" || tagName === Coll.tagName) {
			coll.tag = Coll.tagName;
			return coll;
		}
		if (tagName) coll.tag = tagName;
		return coll;
	}
	function composeCollection(CN, ctx, token, props, onError) {
		const tagToken = props.tag;
		const tagName = !tagToken ? null : ctx.directives.tagName(tagToken.source, (msg) => onError(tagToken, "TAG_RESOLVE_FAILED", msg));
		if (token.type === "block-seq") {
			const { anchor, newlineAfterProp: nl } = props;
			const lastProp = anchor && tagToken ? anchor.offset > tagToken.offset ? anchor : tagToken : anchor ?? tagToken;
			if (lastProp && (!nl || nl.offset < lastProp.offset)) onError(lastProp, "MISSING_CHAR", "Missing newline after block sequence props");
		}
		const expType = token.type === "block-map" ? "map" : token.type === "block-seq" ? "seq" : token.start.source === "{" ? "map" : "seq";
		if (!tagToken || !tagName || tagName === "!" || tagName === YAMLMap.YAMLMap.tagName && expType === "map" || tagName === YAMLSeq.YAMLSeq.tagName && expType === "seq") return resolveCollection(CN, ctx, token, onError, tagName);
		let tag = ctx.schema.tags.find((t) => t.tag === tagName && t.collection === expType);
		if (!tag) {
			const kt = ctx.schema.knownTags[tagName];
			if (kt?.collection === expType) {
				ctx.schema.tags.push(Object.assign({}, kt, { default: false }));
				tag = kt;
			} else {
				if (kt) onError(tagToken, "BAD_COLLECTION_TYPE", `${kt.tag} used for ${expType} collection, but expects ${kt.collection ?? "scalar"}`, true);
				else onError(tagToken, "TAG_RESOLVE_FAILED", `Unresolved tag: ${tagName}`, true);
				return resolveCollection(CN, ctx, token, onError, tagName);
			}
		}
		const coll = resolveCollection(CN, ctx, token, onError, tagName, tag);
		const res = tag.resolve?.(coll, (msg) => onError(tagToken, "TAG_RESOLVE_FAILED", msg), ctx.options) ?? coll;
		const node = identity.isNode(res) ? res : new Scalar.Scalar(res);
		node.range = coll.range;
		node.tag = tagName;
		if (tag?.format) node.format = tag.format;
		return node;
	}
	exports.composeCollection = composeCollection;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-block-scalar.js
var require_resolve_block_scalar = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	function resolveBlockScalar(ctx, scalar, onError) {
		const start = scalar.offset;
		const header = parseBlockScalarHeader(scalar, ctx.options.strict, onError);
		if (!header) return {
			value: "",
			type: null,
			comment: "",
			range: [
				start,
				start,
				start
			]
		};
		const type = header.mode === ">" ? Scalar.Scalar.BLOCK_FOLDED : Scalar.Scalar.BLOCK_LITERAL;
		const lines = scalar.source ? splitLines(scalar.source) : [];
		let chompStart = lines.length;
		for (let i = lines.length - 1; i >= 0; --i) {
			const content = lines[i][1];
			if (content === "" || content === "\r") chompStart = i;
			else break;
		}
		if (chompStart === 0) {
			const value = header.chomp === "+" && lines.length > 0 ? "\n".repeat(Math.max(1, lines.length - 1)) : "";
			let end = start + header.length;
			if (scalar.source) end += scalar.source.length;
			return {
				value,
				type,
				comment: header.comment,
				range: [
					start,
					end,
					end
				]
			};
		}
		let trimIndent = scalar.indent + header.indent;
		let offset = scalar.offset + header.length;
		let contentStart = 0;
		for (let i = 0; i < chompStart; ++i) {
			const [indent, content] = lines[i];
			if (content === "" || content === "\r") {
				if (header.indent === 0 && indent.length > trimIndent) trimIndent = indent.length;
			} else {
				if (indent.length < trimIndent) onError(offset + indent.length, "MISSING_CHAR", "Block scalars with more-indented leading empty lines must use an explicit indentation indicator");
				if (header.indent === 0) trimIndent = indent.length;
				contentStart = i;
				if (trimIndent === 0 && !ctx.atRoot) onError(offset, "BAD_INDENT", "Block scalar values in collections must be indented");
				break;
			}
			offset += indent.length + content.length + 1;
		}
		for (let i = lines.length - 1; i >= chompStart; --i) if (lines[i][0].length > trimIndent) chompStart = i + 1;
		let value = "";
		let sep = "";
		let prevMoreIndented = false;
		for (let i = 0; i < contentStart; ++i) value += lines[i][0].slice(trimIndent) + "\n";
		for (let i = contentStart; i < chompStart; ++i) {
			let [indent, content] = lines[i];
			offset += indent.length + content.length + 1;
			const crlf = content[content.length - 1] === "\r";
			if (crlf) content = content.slice(0, -1);
			/* istanbul ignore if already caught in lexer */
			if (content && indent.length < trimIndent) {
				const message = `Block scalar lines must not be less indented than their ${header.indent ? "explicit indentation indicator" : "first line"}`;
				onError(offset - content.length - (crlf ? 2 : 1), "BAD_INDENT", message);
				indent = "";
			}
			if (type === Scalar.Scalar.BLOCK_LITERAL) {
				value += sep + indent.slice(trimIndent) + content;
				sep = "\n";
			} else if (indent.length > trimIndent || content[0] === "	") {
				if (sep === " ") sep = "\n";
				else if (!prevMoreIndented && sep === "\n") sep = "\n\n";
				value += sep + indent.slice(trimIndent) + content;
				sep = "\n";
				prevMoreIndented = true;
			} else if (content === "") {
				if (sep === "\n") value += "\n";
				else sep = "\n";
			} else {
				value += sep + content;
				sep = " ";
				prevMoreIndented = false;
			}
		}
		switch (header.chomp) {
			case "-": break;
			case "+":
				for (let i = chompStart; i < lines.length; ++i) value += "\n" + lines[i][0].slice(trimIndent);
				if (value[value.length - 1] !== "\n") value += "\n";
				break;
			default: value += "\n";
		}
		const end = start + header.length + scalar.source.length;
		return {
			value,
			type,
			comment: header.comment,
			range: [
				start,
				end,
				end
			]
		};
	}
	function parseBlockScalarHeader({ offset, props }, strict, onError) {
		/* istanbul ignore if should not happen */
		if (props[0].type !== "block-scalar-header") {
			onError(props[0], "IMPOSSIBLE", "Block scalar header not found");
			return null;
		}
		const { source } = props[0];
		const mode = source[0];
		let indent = 0;
		let chomp = "";
		let error = -1;
		for (let i = 1; i < source.length; ++i) {
			const ch = source[i];
			if (!chomp && (ch === "-" || ch === "+")) chomp = ch;
			else {
				const n = Number(ch);
				if (!indent && n) indent = n;
				else if (error === -1) error = offset + i;
			}
		}
		if (error !== -1) onError(error, "UNEXPECTED_TOKEN", `Block scalar header includes extra characters: ${source}`);
		let hasSpace = false;
		let comment = "";
		let length = source.length;
		for (let i = 1; i < props.length; ++i) {
			const token = props[i];
			switch (token.type) {
				case "space": hasSpace = true;
				case "newline":
					length += token.source.length;
					break;
				case "comment":
					if (strict && !hasSpace) onError(token, "MISSING_CHAR", "Comments must be separated from other tokens by white space characters");
					length += token.source.length;
					comment = token.source.substring(1);
					break;
				case "error":
					onError(token, "UNEXPECTED_TOKEN", token.message);
					length += token.source.length;
					break;
				/* istanbul ignore next should not happen */
				default: {
					onError(token, "UNEXPECTED_TOKEN", `Unexpected token in block scalar header: ${token.type}`);
					const ts = token.source;
					if (ts && typeof ts === "string") length += ts.length;
				}
			}
		}
		return {
			mode,
			indent,
			chomp,
			comment,
			length
		};
	}
	/** @returns Array of lines split up as `[indent, content]` */
	function splitLines(source) {
		const split = source.split(/\n( *)/);
		const first = split[0];
		const m = first.match(/^( *)/);
		const lines = [m?.[1] ? [m[1], first.slice(m[1].length)] : ["", first]];
		for (let i = 1; i < split.length; i += 2) lines.push([split[i], split[i + 1]]);
		return lines;
	}
	exports.resolveBlockScalar = resolveBlockScalar;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/resolve-flow-scalar.js
var require_resolve_flow_scalar = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Scalar = require_Scalar();
	var resolveEnd = require_resolve_end();
	function resolveFlowScalar(scalar, strict, onError) {
		const { offset, type, source, end } = scalar;
		let _type;
		let value;
		const _onError = (rel, code, msg) => onError(offset + rel, code, msg);
		switch (type) {
			case "scalar":
				_type = Scalar.Scalar.PLAIN;
				value = plainValue(source, _onError);
				break;
			case "single-quoted-scalar":
				_type = Scalar.Scalar.QUOTE_SINGLE;
				value = singleQuotedValue(source, _onError);
				break;
			case "double-quoted-scalar":
				_type = Scalar.Scalar.QUOTE_DOUBLE;
				value = doubleQuotedValue(source, _onError);
				break;
			/* istanbul ignore next should not happen */
			default:
				onError(scalar, "UNEXPECTED_TOKEN", `Expected a flow scalar value, but found: ${type}`);
				return {
					value: "",
					type: null,
					comment: "",
					range: [
						offset,
						offset + source.length,
						offset + source.length
					]
				};
		}
		const valueEnd = offset + source.length;
		const re = resolveEnd.resolveEnd(end, valueEnd, strict, onError);
		return {
			value,
			type: _type,
			comment: re.comment,
			range: [
				offset,
				valueEnd,
				re.offset
			]
		};
	}
	function plainValue(source, onError) {
		let badChar = "";
		switch (source[0]) {
			/* istanbul ignore next should not happen */
			case "	":
				badChar = "a tab character";
				break;
			case ",":
				badChar = "flow indicator character ,";
				break;
			case "%":
				badChar = "directive indicator character %";
				break;
			case "|":
			case ">":
				badChar = `block scalar indicator ${source[0]}`;
				break;
			case "@":
			case "`": badChar = `reserved character ${source[0]}`;
		}
		if (badChar) onError(0, "BAD_SCALAR_START", `Plain value cannot start with ${badChar}`);
		return unfoldLines(source);
	}
	function singleQuotedValue(source, onError) {
		if (source[source.length - 1] !== "'" || source.length === 1) onError(source.length, "MISSING_CHAR", "Missing closing 'quote");
		return unfoldLines(source.slice(1, -1)).replace(/''/g, "'");
	}
	function unfoldLines(source) {
		const line = /(.*?)\r?\n/sy;
		let match = line.exec(source);
		if (!match) return source;
		/**
		* The negative lookbehinds in these RegExps are to
		* prevent causing a polynomial search time in certain cases.
		*
		* The try-catch is for Safari < 16.4 and other old browsers:
		* https://caniuse.com/js-regexp-lookbehind
		*/
		let trimEnd, trimBoth;
		try {
			trimEnd = /* @__PURE__ */ new RegExp("(?<![ 	])[ 	]+$");
			trimBoth = /* @__PURE__ */ new RegExp("^[ 	]+|(?<![ 	])[ 	]+$", "g");
		} catch {
			trimEnd = /[ \t]+$/;
			trimBoth = /^[ \t]+|[ \t]+$/g;
		}
		let res = match[1].replace(trimEnd, "");
		let sep = " ";
		let pos = line.lastIndex;
		while (match = line.exec(source)) {
			const lm = match[1].replace(trimBoth, "");
			if (lm === "") {
				if (sep === "\n") res += sep;
				else sep = "\n";
			} else {
				res += sep + lm;
				sep = " ";
			}
			pos = line.lastIndex;
		}
		const last = /[ \t]*(.*)/sy;
		last.lastIndex = pos;
		match = last.exec(source);
		return res + sep + (match?.[1] ?? "");
	}
	function doubleQuotedValue(source, onError) {
		let res = "";
		for (let i = 1; i < source.length - 1; ++i) {
			const ch = source[i];
			if (ch === "\r" && source[i + 1] === "\n") continue;
			if (ch === "\n") {
				const { fold, offset } = foldNewline(source, i);
				res += fold;
				i = offset;
			} else if (ch === "\\") {
				let next = source[++i];
				const cc = escapeCodes[next];
				if (cc) res += cc;
				else if (next === "\n") {
					next = source[i + 1];
					while (next === " " || next === "	") next = source[++i + 1];
				} else if (next === "\r" && source[i + 1] === "\n") {
					next = source[++i + 1];
					while (next === " " || next === "	") next = source[++i + 1];
				} else if (next === "x" || next === "u" || next === "U") {
					const length = next === "x" ? 2 : next === "u" ? 4 : 8;
					res += parseCharCode(source, i + 1, length, onError);
					i += length;
				} else {
					const raw = source.substr(i - 1, 2);
					onError(i - 1, "BAD_DQ_ESCAPE", `Invalid escape sequence ${raw}`);
					res += raw;
				}
			} else if (ch === " " || ch === "	") {
				const wsStart = i;
				let next = source[i + 1];
				while (next === " " || next === "	") next = source[++i + 1];
				if (next !== "\n" && !(next === "\r" && source[i + 2] === "\n")) res += i > wsStart ? source.slice(wsStart, i + 1) : ch;
			} else res += ch;
		}
		if (source[source.length - 1] !== "\"" || source.length === 1) onError(source.length, "MISSING_CHAR", "Missing closing \"quote");
		return res;
	}
	/**
	* Fold a single newline into a space, multiple newlines to N - 1 newlines.
	* Presumes `source[offset] === '\n'`
	*/
	function foldNewline(source, offset) {
		let fold = "";
		let ch = source[offset + 1];
		while (ch === " " || ch === "	" || ch === "\n" || ch === "\r") {
			if (ch === "\r" && source[offset + 2] !== "\n") break;
			if (ch === "\n") fold += "\n";
			offset += 1;
			ch = source[offset + 1];
		}
		if (!fold) fold = " ";
		return {
			fold,
			offset
		};
	}
	const escapeCodes = {
		"0": "\0",
		a: "\x07",
		b: "\b",
		e: "\x1B",
		f: "\f",
		n: "\n",
		r: "\r",
		t: "	",
		v: "\v",
		N: "",
		_: "\xA0",
		L: "\u2028",
		P: "\u2029",
		" ": " ",
		"\"": "\"",
		"/": "/",
		"\\": "\\",
		"	": "	"
	};
	function parseCharCode(source, offset, length, onError) {
		const cc = source.substr(offset, length);
		const code = cc.length === length && /^[0-9a-fA-F]+$/.test(cc) ? parseInt(cc, 16) : NaN;
		try {
			return String.fromCodePoint(code);
		} catch {
			const raw = source.substr(offset - 2, length + 2);
			onError(offset - 2, "BAD_DQ_ESCAPE", `Invalid escape sequence ${raw}`);
			return raw;
		}
	}
	exports.resolveFlowScalar = resolveFlowScalar;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/compose-scalar.js
var require_compose_scalar = /* @__PURE__ */ __commonJSMin(((exports) => {
	var identity = require_identity();
	var Scalar = require_Scalar();
	var resolveBlockScalar = require_resolve_block_scalar();
	var resolveFlowScalar = require_resolve_flow_scalar();
	function composeScalar(ctx, token, tagToken, onError) {
		const { value, type, comment, range } = token.type === "block-scalar" ? resolveBlockScalar.resolveBlockScalar(ctx, token, onError) : resolveFlowScalar.resolveFlowScalar(token, ctx.options.strict, onError);
		const tagName = tagToken ? ctx.directives.tagName(tagToken.source, (msg) => onError(tagToken, "TAG_RESOLVE_FAILED", msg)) : null;
		let tag;
		if (ctx.options.stringKeys && ctx.atKey) tag = ctx.schema[identity.SCALAR];
		else if (tagName) tag = findScalarTagByName(ctx.schema, value, tagName, tagToken, onError);
		else if (token.type === "scalar") tag = findScalarTagByTest(ctx, value, token, onError);
		else tag = ctx.schema[identity.SCALAR];
		let scalar;
		try {
			const res = tag.resolve(value, (msg) => onError(tagToken ?? token, "TAG_RESOLVE_FAILED", msg), ctx.options);
			scalar = identity.isScalar(res) ? res : new Scalar.Scalar(res);
		} catch (error) {
			const msg = error instanceof Error ? error.message : String(error);
			onError(tagToken ?? token, "TAG_RESOLVE_FAILED", msg);
			scalar = new Scalar.Scalar(value);
		}
		scalar.range = range;
		scalar.source = value;
		if (type) scalar.type = type;
		if (tagName) scalar.tag = tagName;
		if (tag.format) scalar.format = tag.format;
		if (comment) scalar.comment = comment;
		return scalar;
	}
	function findScalarTagByName(schema, value, tagName, tagToken, onError) {
		if (tagName === "!") return schema[identity.SCALAR];
		const matchWithTest = [];
		for (const tag of schema.tags) if (!tag.collection && tag.tag === tagName) {
			if (tag.default && tag.test) matchWithTest.push(tag);
			else return tag;
		}
		for (const tag of matchWithTest) if (tag.test?.test(value)) return tag;
		const kt = schema.knownTags[tagName];
		if (kt && !kt.collection) {
			schema.tags.push(Object.assign({}, kt, {
				default: false,
				test: void 0
			}));
			return kt;
		}
		onError(tagToken, "TAG_RESOLVE_FAILED", `Unresolved tag: ${tagName}`, tagName !== "tag:yaml.org,2002:str");
		return schema[identity.SCALAR];
	}
	function findScalarTagByTest({ atKey, directives, schema }, value, token, onError) {
		const tag = schema.tags.find((tag) => (tag.default === true || atKey && tag.default === "key") && tag.test?.test(value)) || schema[identity.SCALAR];
		if (schema.compat) {
			const compat = schema.compat.find((tag) => tag.default && tag.test?.test(value)) ?? schema[identity.SCALAR];
			if (tag.tag !== compat.tag) onError(token, "TAG_RESOLVE_FAILED", `Value may be parsed as either ${directives.tagString(tag.tag)} or ${directives.tagString(compat.tag)}`, true);
		}
		return tag;
	}
	exports.composeScalar = composeScalar;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/util-empty-scalar-position.js
var require_util_empty_scalar_position = /* @__PURE__ */ __commonJSMin(((exports) => {
	function emptyScalarPosition(offset, before, pos) {
		if (before) {
			pos ?? (pos = before.length);
			for (let i = pos - 1; i >= 0; --i) {
				let st = before[i];
				switch (st.type) {
					case "space":
					case "comment":
					case "newline":
						offset -= st.source.length;
						continue;
				}
				st = before[++i];
				while (st?.type === "space") {
					offset += st.source.length;
					st = before[++i];
				}
				break;
			}
		}
		return offset;
	}
	exports.emptyScalarPosition = emptyScalarPosition;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/compose-node.js
var require_compose_node = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Alias = require_Alias();
	var identity = require_identity();
	var composeCollection = require_compose_collection();
	var composeScalar = require_compose_scalar();
	var resolveEnd = require_resolve_end();
	var utilEmptyScalarPosition = require_util_empty_scalar_position();
	const CN = {
		composeNode,
		composeEmptyNode
	};
	function composeNode(ctx, token, props, onError) {
		const atKey = ctx.atKey;
		const { spaceBefore, comment, anchor, tag } = props;
		let node;
		let isSrcToken = true;
		switch (token.type) {
			case "alias":
				node = composeAlias(ctx, token, onError);
				if (anchor || tag) onError(token, "ALIAS_PROPS", "An alias node must not specify any properties");
				break;
			case "scalar":
			case "single-quoted-scalar":
			case "double-quoted-scalar":
			case "block-scalar":
				node = composeScalar.composeScalar(ctx, token, tag, onError);
				if (anchor) node.anchor = anchor.source.substring(1);
				break;
			case "block-map":
			case "block-seq":
			case "flow-collection":
				try {
					node = composeCollection.composeCollection(CN, ctx, token, props, onError);
					if (anchor) node.anchor = anchor.source.substring(1);
				} catch (error) {
					onError(token, "RESOURCE_EXHAUSTION", error instanceof Error ? error.message : String(error));
				}
				break;
			default:
				onError(token, "UNEXPECTED_TOKEN", token.type === "error" ? token.message : `Unsupported token (type: ${token.type})`);
				isSrcToken = false;
		}
		node ?? (node = composeEmptyNode(ctx, token.offset, void 0, null, props, onError));
		if (anchor && node.anchor === "") onError(anchor, "BAD_ALIAS", "Anchor cannot be an empty string");
		if (atKey && ctx.options.stringKeys && (!identity.isScalar(node) || typeof node.value !== "string" || node.tag && node.tag !== "tag:yaml.org,2002:str")) onError(tag ?? token, "NON_STRING_KEY", "With stringKeys, all keys must be strings");
		if (spaceBefore) node.spaceBefore = true;
		if (comment) {
			if (token.type === "scalar" && token.source === "") node.comment = comment;
			else node.commentBefore = comment;
		}
		if (ctx.options.keepSourceTokens && isSrcToken) node.srcToken = token;
		return node;
	}
	function composeEmptyNode(ctx, offset, before, pos, { spaceBefore, comment, anchor, tag, end }, onError) {
		const token = {
			type: "scalar",
			offset: utilEmptyScalarPosition.emptyScalarPosition(offset, before, pos),
			indent: -1,
			source: ""
		};
		const node = composeScalar.composeScalar(ctx, token, tag, onError);
		if (anchor) {
			node.anchor = anchor.source.substring(1);
			if (node.anchor === "") onError(anchor, "BAD_ALIAS", "Anchor cannot be an empty string");
		}
		if (spaceBefore) node.spaceBefore = true;
		if (comment) {
			node.comment = comment;
			node.range[2] = end;
		}
		return node;
	}
	function composeAlias({ options }, { offset, source, end }, onError) {
		const alias = new Alias.Alias(source.substring(1));
		if (alias.source === "") onError(offset, "BAD_ALIAS", "Alias cannot be an empty string");
		if (alias.source.endsWith(":")) onError(offset + source.length - 1, "BAD_ALIAS", "Alias ending in : is ambiguous", true);
		const valueEnd = offset + source.length;
		const re = resolveEnd.resolveEnd(end, valueEnd, options.strict, onError);
		alias.range = [
			offset,
			valueEnd,
			re.offset
		];
		if (re.comment) alias.comment = re.comment;
		return alias;
	}
	exports.composeEmptyNode = composeEmptyNode;
	exports.composeNode = composeNode;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/compose-doc.js
var require_compose_doc = /* @__PURE__ */ __commonJSMin(((exports) => {
	var Document = require_Document();
	var composeNode = require_compose_node();
	var resolveEnd = require_resolve_end();
	var resolveProps = require_resolve_props();
	function composeDoc(options, directives, { offset, start, value, end }, onError) {
		const opts = Object.assign({ _directives: directives }, options);
		const doc = new Document.Document(void 0, opts);
		const ctx = {
			atKey: false,
			atRoot: true,
			directives: doc.directives,
			options: doc.options,
			schema: doc.schema
		};
		const props = resolveProps.resolveProps(start, {
			indicator: "doc-start",
			next: value ?? end?.[0],
			offset,
			onError,
			parentIndent: 0,
			startOnNewline: true
		});
		if (props.found) {
			doc.directives.docStart = true;
			if (value && (value.type === "block-map" || value.type === "block-seq") && !props.hasNewline) onError(props.end, "MISSING_CHAR", "Block collection cannot start on same line with directives-end marker");
		}
		doc.contents = value ? composeNode.composeNode(ctx, value, props, onError) : composeNode.composeEmptyNode(ctx, props.end, start, null, props, onError);
		const contentEnd = doc.contents.range[2];
		const re = resolveEnd.resolveEnd(end, contentEnd, false, onError);
		if (re.comment) doc.comment = re.comment;
		doc.range = [
			offset,
			contentEnd,
			re.offset
		];
		return doc;
	}
	exports.composeDoc = composeDoc;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/compose/composer.js
var require_composer = /* @__PURE__ */ __commonJSMin(((exports) => {
	var node_process = __require("process");
	var directives = require_directives();
	var Document = require_Document();
	var errors = require_errors();
	var identity = require_identity();
	var composeDoc = require_compose_doc();
	var resolveEnd = require_resolve_end();
	function getErrorPos(src) {
		if (typeof src === "number") return [src, src + 1];
		if (Array.isArray(src)) return src.length === 2 ? src : [src[0], src[1]];
		const { offset, source } = src;
		return [offset, offset + (typeof source === "string" ? source.length : 1)];
	}
	function parsePrelude(prelude) {
		let comment = "";
		let atComment = false;
		let afterEmptyLine = false;
		for (let i = 0; i < prelude.length; ++i) {
			const source = prelude[i];
			switch (source[0]) {
				case "#":
					comment += (comment === "" ? "" : afterEmptyLine ? "\n\n" : "\n") + (source.substring(1) || " ");
					atComment = true;
					afterEmptyLine = false;
					break;
				case "%":
					if (prelude[i + 1]?.[0] !== "#") i += 1;
					atComment = false;
					break;
				default:
					if (!atComment) afterEmptyLine = true;
					atComment = false;
			}
		}
		return {
			comment,
			afterEmptyLine
		};
	}
	/**
	* Compose a stream of CST nodes into a stream of YAML Documents.
	*
	* ```ts
	* import { Composer, Parser } from 'yaml'
	*
	* const src: string = ...
	* const tokens = new Parser().parse(src)
	* const docs = new Composer().compose(tokens)
	* ```
	*/
	var Composer = class {
		constructor(options = {}) {
			this.doc = null;
			this.atDirectives = false;
			this.prelude = [];
			this.errors = [];
			this.warnings = [];
			this.onError = (source, code, message, warning) => {
				const pos = getErrorPos(source);
				if (warning) this.warnings.push(new errors.YAMLWarning(pos, code, message));
				else this.errors.push(new errors.YAMLParseError(pos, code, message));
			};
			this.directives = new directives.Directives({ version: options.version || "1.2" });
			this.options = options;
		}
		decorate(doc, afterDoc) {
			const { comment, afterEmptyLine } = parsePrelude(this.prelude);
			if (comment) {
				const dc = doc.contents;
				if (afterDoc) doc.comment = doc.comment ? `${doc.comment}\n${comment}` : comment;
				else if (afterEmptyLine || doc.directives.docStart || !dc) doc.commentBefore = comment;
				else if (identity.isCollection(dc) && !dc.flow && dc.items.length > 0) {
					let it = dc.items[0];
					if (identity.isPair(it)) it = it.key;
					const cb = it.commentBefore;
					it.commentBefore = cb ? `${comment}\n${cb}` : comment;
				} else {
					const cb = dc.commentBefore;
					dc.commentBefore = cb ? `${comment}\n${cb}` : comment;
				}
			}
			if (afterDoc) {
				for (let i = 0; i < this.errors.length; ++i) doc.errors.push(this.errors[i]);
				for (let i = 0; i < this.warnings.length; ++i) doc.warnings.push(this.warnings[i]);
			} else {
				doc.errors = this.errors;
				doc.warnings = this.warnings;
			}
			this.prelude = [];
			this.errors = [];
			this.warnings = [];
		}
		/**
		* Current stream status information.
		*
		* Mostly useful at the end of input for an empty stream.
		*/
		streamInfo() {
			return {
				comment: parsePrelude(this.prelude).comment,
				directives: this.directives,
				errors: this.errors,
				warnings: this.warnings
			};
		}
		/**
		* Compose tokens into documents.
		*
		* @param forceDoc - If the stream contains no document, still emit a final document including any comments and directives that would be applied to a subsequent document.
		* @param endOffset - Should be set if `forceDoc` is also set, to set the document range end and to indicate errors correctly.
		*/
		*compose(tokens, forceDoc = false, endOffset = -1) {
			for (const token of tokens) yield* this.next(token);
			yield* this.end(forceDoc, endOffset);
		}
		/** Advance the composer by one CST token. */
		*next(token) {
			if (node_process.env.LOG_STREAM) console.dir(token, { depth: null });
			switch (token.type) {
				case "directive":
					this.directives.add(token.source, (offset, message, warning) => {
						const pos = getErrorPos(token);
						pos[0] += offset;
						this.onError(pos, "BAD_DIRECTIVE", message, warning);
					});
					this.prelude.push(token.source);
					this.atDirectives = true;
					break;
				case "document": {
					const doc = composeDoc.composeDoc(this.options, this.directives, token, this.onError);
					if (this.atDirectives && !doc.directives.docStart) this.onError(token, "MISSING_CHAR", "Missing directives-end/doc-start indicator line");
					this.decorate(doc, false);
					if (this.doc) yield this.doc;
					this.doc = doc;
					this.atDirectives = false;
					break;
				}
				case "byte-order-mark":
				case "space": break;
				case "comment":
				case "newline":
					this.prelude.push(token.source);
					break;
				case "error": {
					const msg = token.source ? `${token.message}: ${JSON.stringify(token.source)}` : token.message;
					const error = new errors.YAMLParseError(getErrorPos(token), "UNEXPECTED_TOKEN", msg);
					if (this.atDirectives || !this.doc) this.errors.push(error);
					else this.doc.errors.push(error);
					break;
				}
				case "doc-end": {
					if (!this.doc) {
						this.errors.push(new errors.YAMLParseError(getErrorPos(token), "UNEXPECTED_TOKEN", "Unexpected doc-end without preceding document"));
						break;
					}
					this.doc.directives.docEnd = true;
					const end = resolveEnd.resolveEnd(token.end, token.offset + token.source.length, this.doc.options.strict, this.onError);
					this.decorate(this.doc, true);
					if (end.comment) {
						const dc = this.doc.comment;
						this.doc.comment = dc ? `${dc}\n${end.comment}` : end.comment;
					}
					this.doc.range[2] = end.offset;
					break;
				}
				default: this.errors.push(new errors.YAMLParseError(getErrorPos(token), "UNEXPECTED_TOKEN", `Unsupported token ${token.type}`));
			}
		}
		/**
		* Call at end of input to yield any remaining document.
		*
		* @param forceDoc - If the stream contains no document, still emit a final document including any comments and directives that would be applied to a subsequent document.
		* @param endOffset - Should be set if `forceDoc` is also set, to set the document range end and to indicate errors correctly.
		*/
		*end(forceDoc = false, endOffset = -1) {
			if (this.doc) {
				this.decorate(this.doc, true);
				yield this.doc;
				this.doc = null;
			} else if (forceDoc) {
				const opts = Object.assign({ _directives: this.directives }, this.options);
				const doc = new Document.Document(void 0, opts);
				if (this.atDirectives) this.onError(endOffset, "MISSING_CHAR", "Missing directives-end indicator line");
				doc.range = [
					0,
					endOffset,
					endOffset
				];
				this.decorate(doc, false);
				yield doc;
			}
		}
	};
	exports.Composer = Composer;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/cst-scalar.js
var require_cst_scalar = /* @__PURE__ */ __commonJSMin(((exports) => {
	var resolveBlockScalar = require_resolve_block_scalar();
	var resolveFlowScalar = require_resolve_flow_scalar();
	var errors = require_errors();
	var stringifyString = require_stringifyString();
	function resolveAsScalar(token, strict = true, onError) {
		if (token) {
			const _onError = (pos, code, message) => {
				const offset = typeof pos === "number" ? pos : Array.isArray(pos) ? pos[0] : pos.offset;
				if (onError) onError(offset, code, message);
				else throw new errors.YAMLParseError([offset, offset + 1], code, message);
			};
			switch (token.type) {
				case "scalar":
				case "single-quoted-scalar":
				case "double-quoted-scalar": return resolveFlowScalar.resolveFlowScalar(token, strict, _onError);
				case "block-scalar": return resolveBlockScalar.resolveBlockScalar({ options: { strict } }, token, _onError);
			}
		}
		return null;
	}
	/**
	* Create a new scalar token with `value`
	*
	* Values that represent an actual string but may be parsed as a different type should use a `type` other than `'PLAIN'`,
	* as this function does not support any schema operations and won't check for such conflicts.
	*
	* @param value The string representation of the value, which will have its content properly indented.
	* @param context.end Comments and whitespace after the end of the value, or after the block scalar header. If undefined, a newline will be added.
	* @param context.implicitKey Being within an implicit key may affect the resolved type of the token's value.
	* @param context.indent The indent level of the token.
	* @param context.inFlow Is this scalar within a flow collection? This may affect the resolved type of the token's value.
	* @param context.offset The offset position of the token.
	* @param context.type The preferred type of the scalar token. If undefined, the previous type of the `token` will be used, defaulting to `'PLAIN'`.
	*/
	function createScalarToken(value, context) {
		const { implicitKey = false, indent, inFlow = false, offset = -1, type = "PLAIN" } = context;
		const source = stringifyString.stringifyString({
			type,
			value
		}, {
			implicitKey,
			indent: indent > 0 ? " ".repeat(indent) : "",
			inFlow,
			options: {
				blockQuote: true,
				lineWidth: -1
			}
		});
		const end = context.end ?? [{
			type: "newline",
			offset: -1,
			indent,
			source: "\n"
		}];
		switch (source[0]) {
			case "|":
			case ">": {
				const he = source.indexOf("\n");
				const head = source.substring(0, he);
				const body = source.substring(he + 1) + "\n";
				const props = [{
					type: "block-scalar-header",
					offset,
					indent,
					source: head
				}];
				if (!addEndtoBlockProps(props, end)) props.push({
					type: "newline",
					offset: -1,
					indent,
					source: "\n"
				});
				return {
					type: "block-scalar",
					offset,
					indent,
					props,
					source: body
				};
			}
			case "\"": return {
				type: "double-quoted-scalar",
				offset,
				indent,
				source,
				end
			};
			case "'": return {
				type: "single-quoted-scalar",
				offset,
				indent,
				source,
				end
			};
			default: return {
				type: "scalar",
				offset,
				indent,
				source,
				end
			};
		}
	}
	/**
	* Set the value of `token` to the given string `value`, overwriting any previous contents and type that it may have.
	*
	* Best efforts are made to retain any comments previously associated with the `token`,
	* though all contents within a collection's `items` will be overwritten.
	*
	* Values that represent an actual string but may be parsed as a different type should use a `type` other than `'PLAIN'`,
	* as this function does not support any schema operations and won't check for such conflicts.
	*
	* @param token Any token. If it does not include an `indent` value, the value will be stringified as if it were an implicit key.
	* @param value The string representation of the value, which will have its content properly indented.
	* @param context.afterKey In most cases, values after a key should have an additional level of indentation.
	* @param context.implicitKey Being within an implicit key may affect the resolved type of the token's value.
	* @param context.inFlow Being within a flow collection may affect the resolved type of the token's value.
	* @param context.type The preferred type of the scalar token. If undefined, the previous type of the `token` will be used, defaulting to `'PLAIN'`.
	*/
	function setScalarValue(token, value, context = {}) {
		let { afterKey = false, implicitKey = false, inFlow = false, type } = context;
		let indent = "indent" in token ? token.indent : null;
		if (afterKey && typeof indent === "number") indent += 2;
		if (!type) switch (token.type) {
			case "single-quoted-scalar":
				type = "QUOTE_SINGLE";
				break;
			case "double-quoted-scalar":
				type = "QUOTE_DOUBLE";
				break;
			case "block-scalar": {
				const header = token.props[0];
				if (header.type !== "block-scalar-header") throw new Error("Invalid block scalar header");
				type = header.source[0] === ">" ? "BLOCK_FOLDED" : "BLOCK_LITERAL";
				break;
			}
			default: type = "PLAIN";
		}
		const source = stringifyString.stringifyString({
			type,
			value
		}, {
			implicitKey: implicitKey || indent === null,
			indent: indent !== null && indent > 0 ? " ".repeat(indent) : "",
			inFlow,
			options: {
				blockQuote: true,
				lineWidth: -1
			}
		});
		switch (source[0]) {
			case "|":
			case ">":
				setBlockScalarValue(token, source);
				break;
			case "\"":
				setFlowScalarValue(token, source, "double-quoted-scalar");
				break;
			case "'":
				setFlowScalarValue(token, source, "single-quoted-scalar");
				break;
			default: setFlowScalarValue(token, source, "scalar");
		}
	}
	function setBlockScalarValue(token, source) {
		const he = source.indexOf("\n");
		const head = source.substring(0, he);
		const body = source.substring(he + 1) + "\n";
		if (token.type === "block-scalar") {
			const header = token.props[0];
			if (header.type !== "block-scalar-header") throw new Error("Invalid block scalar header");
			header.source = head;
			token.source = body;
		} else {
			const { offset } = token;
			const indent = "indent" in token ? token.indent : -1;
			const props = [{
				type: "block-scalar-header",
				offset,
				indent,
				source: head
			}];
			if (!addEndtoBlockProps(props, "end" in token ? token.end : void 0)) props.push({
				type: "newline",
				offset: -1,
				indent,
				source: "\n"
			});
			for (const key of Object.keys(token)) if (key !== "type" && key !== "offset") delete token[key];
			Object.assign(token, {
				type: "block-scalar",
				indent,
				props,
				source: body
			});
		}
	}
	/** @returns `true` if last token is a newline */
	function addEndtoBlockProps(props, end) {
		if (end) for (const st of end) switch (st.type) {
			case "space":
			case "comment":
				props.push(st);
				break;
			case "newline":
				props.push(st);
				return true;
		}
		return false;
	}
	function setFlowScalarValue(token, source, type) {
		switch (token.type) {
			case "scalar":
			case "double-quoted-scalar":
			case "single-quoted-scalar":
				token.type = type;
				token.source = source;
				break;
			case "block-scalar": {
				const end = token.props.slice(1);
				let oa = source.length;
				if (token.props[0].type === "block-scalar-header") oa -= token.props[0].source.length;
				for (const tok of end) tok.offset += oa;
				delete token.props;
				Object.assign(token, {
					type,
					source,
					end
				});
				break;
			}
			case "block-map":
			case "block-seq": {
				const nl = {
					type: "newline",
					offset: token.offset + source.length,
					indent: token.indent,
					source: "\n"
				};
				delete token.items;
				Object.assign(token, {
					type,
					source,
					end: [nl]
				});
				break;
			}
			default: {
				const indent = "indent" in token ? token.indent : -1;
				const end = "end" in token && Array.isArray(token.end) ? token.end.filter((st) => st.type === "space" || st.type === "comment" || st.type === "newline") : [];
				for (const key of Object.keys(token)) if (key !== "type" && key !== "offset") delete token[key];
				Object.assign(token, {
					type,
					indent,
					source,
					end
				});
			}
		}
	}
	exports.createScalarToken = createScalarToken;
	exports.resolveAsScalar = resolveAsScalar;
	exports.setScalarValue = setScalarValue;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/cst-stringify.js
var require_cst_stringify = /* @__PURE__ */ __commonJSMin(((exports) => {
	/**
	* Stringify a CST document, token, or collection item
	*
	* Fair warning: This applies no validation whatsoever, and
	* simply concatenates the sources in their logical order.
	*/
	const stringify = (cst) => "type" in cst ? stringifyToken(cst) : stringifyItem(cst);
	function stringifyToken(token) {
		switch (token.type) {
			case "block-scalar": {
				let res = "";
				for (const tok of token.props) res += stringifyToken(tok);
				return res + token.source;
			}
			case "block-map":
			case "block-seq": {
				let res = "";
				for (const item of token.items) res += stringifyItem(item);
				return res;
			}
			case "flow-collection": {
				let res = token.start.source;
				for (const item of token.items) res += stringifyItem(item);
				for (const st of token.end) res += st.source;
				return res;
			}
			case "document": {
				let res = stringifyItem(token);
				if (token.end) for (const st of token.end) res += st.source;
				return res;
			}
			default: {
				let res = token.source;
				if ("end" in token && token.end) for (const st of token.end) res += st.source;
				return res;
			}
		}
	}
	function stringifyItem({ start, key, sep, value }) {
		let res = "";
		for (const st of start) res += st.source;
		if (key) res += stringifyToken(key);
		if (sep) for (const st of sep) res += st.source;
		if (value) res += stringifyToken(value);
		return res;
	}
	exports.stringify = stringify;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/cst-visit.js
var require_cst_visit = /* @__PURE__ */ __commonJSMin(((exports) => {
	const BREAK = Symbol("break visit");
	const SKIP = Symbol("skip children");
	const REMOVE = Symbol("remove item");
	/**
	* Apply a visitor to a CST document or item.
	*
	* Walks through the tree (depth-first) starting from the root, calling a
	* `visitor` function with two arguments when entering each item:
	*   - `item`: The current item, which included the following members:
	*     - `start: SourceToken[]` – Source tokens before the key or value,
	*       possibly including its anchor or tag.
	*     - `key?: Token | null` – Set for pair values. May then be `null`, if
	*       the key before the `:` separator is empty.
	*     - `sep?: SourceToken[]` – Source tokens between the key and the value,
	*       which should include the `:` map value indicator if `value` is set.
	*     - `value?: Token` – The value of a sequence item, or of a map pair.
	*   - `path`: The steps from the root to the current node, as an array of
	*     `['key' | 'value', number]` tuples.
	*
	* The return value of the visitor may be used to control the traversal:
	*   - `undefined` (default): Do nothing and continue
	*   - `visit.SKIP`: Do not visit the children of this token, continue with
	*      next sibling
	*   - `visit.BREAK`: Terminate traversal completely
	*   - `visit.REMOVE`: Remove the current item, then continue with the next one
	*   - `number`: Set the index of the next step. This is useful especially if
	*     the index of the current token has changed.
	*   - `function`: Define the next visitor for this item. After the original
	*     visitor is called on item entry, next visitors are called after handling
	*     a non-empty `key` and when exiting the item.
	*/
	function visit(cst, visitor) {
		if ("type" in cst && cst.type === "document") cst = {
			start: cst.start,
			value: cst.value
		};
		_visit(Object.freeze([]), cst, visitor);
	}
	/** Terminate visit traversal completely */
	visit.BREAK = BREAK;
	/** Do not visit the children of the current item */
	visit.SKIP = SKIP;
	/** Remove the current item */
	visit.REMOVE = REMOVE;
	/** Find the item at `path` from `cst` as the root */
	visit.itemAtPath = (cst, path) => {
		let item = cst;
		for (const [field, index] of path) {
			const tok = item?.[field];
			if (tok && "items" in tok) item = tok.items[index];
			else return void 0;
		}
		return item;
	};
	/**
	* Get the immediate parent collection of the item at `path` from `cst` as the root.
	*
	* Throws an error if the collection is not found, which should never happen if the item itself exists.
	*/
	visit.parentCollection = (cst, path) => {
		const parent = visit.itemAtPath(cst, path.slice(0, -1));
		const field = path[path.length - 1][0];
		const coll = parent?.[field];
		if (coll && "items" in coll) return coll;
		throw new Error("Parent collection not found");
	};
	function _visit(path, item, visitor) {
		let ctrl = visitor(item, path);
		if (typeof ctrl === "symbol") return ctrl;
		for (const field of ["key", "value"]) {
			const token = item[field];
			if (token && "items" in token) {
				for (let i = 0; i < token.items.length; ++i) {
					const ci = _visit(Object.freeze(path.concat([[field, i]])), token.items[i], visitor);
					if (typeof ci === "number") i = ci - 1;
					else if (ci === BREAK) return BREAK;
					else if (ci === REMOVE) {
						token.items.splice(i, 1);
						i -= 1;
					}
				}
				if (typeof ctrl === "function" && field === "key") ctrl = ctrl(item, path);
			}
		}
		return typeof ctrl === "function" ? ctrl(item, path) : ctrl;
	}
	exports.visit = visit;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/cst.js
var require_cst = /* @__PURE__ */ __commonJSMin(((exports) => {
	var cstScalar = require_cst_scalar();
	var cstStringify = require_cst_stringify();
	var cstVisit = require_cst_visit();
	/** The byte order mark */
	const BOM = "﻿";
	/** Start of doc-mode */
	const DOCUMENT = "";
	/** Unexpected end of flow-mode */
	const FLOW_END = "";
	/** Next token is a scalar value */
	const SCALAR = "";
	/** @returns `true` if `token` is a flow or block collection */
	const isCollection = (token) => !!token && "items" in token;
	/** @returns `true` if `token` is a flow or block scalar; not an alias */
	const isScalar = (token) => !!token && (token.type === "scalar" || token.type === "single-quoted-scalar" || token.type === "double-quoted-scalar" || token.type === "block-scalar");
	/* istanbul ignore next */
	/** Get a printable representation of a lexer token */
	function prettyToken(token) {
		switch (token) {
			case BOM: return "<BOM>";
			case DOCUMENT: return "<DOC>";
			case FLOW_END: return "<FLOW_END>";
			case SCALAR: return "<SCALAR>";
			default: return JSON.stringify(token);
		}
	}
	/** Identify the type of a lexer token. May return `null` for unknown tokens. */
	function tokenType(source) {
		switch (source) {
			case BOM: return "byte-order-mark";
			case DOCUMENT: return "doc-mode";
			case FLOW_END: return "flow-error-end";
			case SCALAR: return "scalar";
			case "---": return "doc-start";
			case "...": return "doc-end";
			case "":
			case "\n":
			case "\r\n": return "newline";
			case "-": return "seq-item-ind";
			case "?": return "explicit-key-ind";
			case ":": return "map-value-ind";
			case "{": return "flow-map-start";
			case "}": return "flow-map-end";
			case "[": return "flow-seq-start";
			case "]": return "flow-seq-end";
			case ",": return "comma";
		}
		switch (source[0]) {
			case " ":
			case "	": return "space";
			case "#": return "comment";
			case "%": return "directive-line";
			case "*": return "alias";
			case "&": return "anchor";
			case "!": return "tag";
			case "'": return "single-quoted-scalar";
			case "\"": return "double-quoted-scalar";
			case "|":
			case ">": return "block-scalar-header";
		}
		return null;
	}
	exports.createScalarToken = cstScalar.createScalarToken;
	exports.resolveAsScalar = cstScalar.resolveAsScalar;
	exports.setScalarValue = cstScalar.setScalarValue;
	exports.stringify = cstStringify.stringify;
	exports.visit = cstVisit.visit;
	exports.BOM = BOM;
	exports.DOCUMENT = DOCUMENT;
	exports.FLOW_END = FLOW_END;
	exports.SCALAR = SCALAR;
	exports.isCollection = isCollection;
	exports.isScalar = isScalar;
	exports.prettyToken = prettyToken;
	exports.tokenType = tokenType;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/lexer.js
var require_lexer = /* @__PURE__ */ __commonJSMin(((exports) => {
	var cst = require_cst();
	function isEmpty(ch) {
		switch (ch) {
			case void 0:
			case " ":
			case "\n":
			case "\r":
			case "	": return true;
			default: return false;
		}
	}
	const hexDigits = /* @__PURE__ */ new Set("0123456789ABCDEFabcdef");
	const tagChars = /* @__PURE__ */ new Set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-#;/?:@&=+$_.!~*'()");
	const flowIndicatorChars = /* @__PURE__ */ new Set(",[]{}");
	const invalidAnchorChars = /* @__PURE__ */ new Set(" ,[]{}\n\r	");
	const isNotAnchorChar = (ch) => !ch || invalidAnchorChars.has(ch);
	/**
	* Splits an input string into lexical tokens, i.e. smaller strings that are
	* easily identifiable by `tokens.tokenType()`.
	*
	* Lexing starts always in a "stream" context. Incomplete input may be buffered
	* until a complete token can be emitted.
	*
	* In addition to slices of the original input, the following control characters
	* may also be emitted:
	*
	* - `\x02` (Start of Text): A document starts with the next token
	* - `\x18` (Cancel): Unexpected end of flow-mode (indicates an error)
	* - `\x1f` (Unit Separator): Next token is a scalar value
	* - `\u{FEFF}` (Byte order mark): Emitted separately outside documents
	*/
	var Lexer = class {
		constructor() {
			/**
			* Flag indicating whether the end of the current buffer marks the end of
			* all input
			*/
			this.atEnd = false;
			/**
			* Explicit indent set in block scalar header, as an offset from the current
			* minimum indent, so e.g. set to 1 from a header `|2+`. Set to -1 if not
			* explicitly set.
			*/
			this.blockScalarIndent = -1;
			/**
			* Block scalars that include a + (keep) chomping indicator in their header
			* include trailing empty lines, which are otherwise excluded from the
			* scalar's contents.
			*/
			this.blockScalarKeep = false;
			/** Current input */
			this.buffer = "";
			/**
			* Flag noting whether the map value indicator : can immediately follow this
			* node within a flow context.
			*/
			this.flowKey = false;
			/** Count of surrounding flow collection levels. */
			this.flowLevel = 0;
			/**
			* Minimum level of indentation required for next lines to be parsed as a
			* part of the current scalar value.
			*/
			this.indentNext = 0;
			/** Indentation level of the current line. */
			this.indentValue = 0;
			/** Position of the next \n character. */
			this.lineEndPos = null;
			/** Stores the state of the lexer if reaching the end of incpomplete input */
			this.next = null;
			/** A pointer to `buffer`; the current position of the lexer. */
			this.pos = 0;
		}
		/**
		* Generate YAML tokens from the `source` string. If `incomplete`,
		* a part of the last line may be left as a buffer for the next call.
		*
		* @returns A generator of lexical tokens
		*/
		*lex(source, incomplete = false) {
			if (source) {
				if (typeof source !== "string") throw TypeError("source is not a string");
				this.buffer = this.buffer ? this.buffer + source : source;
				this.lineEndPos = null;
			}
			this.atEnd = !incomplete;
			let next = this.next ?? "stream";
			while (next && (incomplete || this.hasChars(1))) next = yield* this.parseNext(next);
		}
		atLineEnd() {
			let i = this.pos;
			let ch = this.buffer[i];
			while (ch === " " || ch === "	") ch = this.buffer[++i];
			if (!ch || ch === "#" || ch === "\n") return true;
			if (ch === "\r") return this.buffer[i + 1] === "\n";
			return false;
		}
		charAt(n) {
			return this.buffer[this.pos + n];
		}
		continueScalar(offset) {
			let ch = this.buffer[offset];
			if (this.indentNext > 0) {
				let indent = 0;
				while (ch === " ") ch = this.buffer[++indent + offset];
				if (ch === "\r") {
					const next = this.buffer[indent + offset + 1];
					if (next === "\n" || !next && !this.atEnd) return offset + indent + 1;
				}
				return ch === "\n" || indent >= this.indentNext || !ch && !this.atEnd ? offset + indent : -1;
			}
			if (ch === "-" || ch === ".") {
				const dt = this.buffer.substr(offset, 3);
				if ((dt === "---" || dt === "...") && isEmpty(this.buffer[offset + 3])) return -1;
			}
			return offset;
		}
		getLine() {
			let end = this.lineEndPos;
			if (typeof end !== "number" || end !== -1 && end < this.pos) {
				end = this.buffer.indexOf("\n", this.pos);
				this.lineEndPos = end;
			}
			if (end === -1) return this.atEnd ? this.buffer.substring(this.pos) : null;
			if (this.buffer[end - 1] === "\r") end -= 1;
			return this.buffer.substring(this.pos, end);
		}
		hasChars(n) {
			return this.pos + n <= this.buffer.length;
		}
		setNext(state) {
			this.buffer = this.buffer.substring(this.pos);
			this.pos = 0;
			this.lineEndPos = null;
			this.next = state;
			return null;
		}
		peek(n) {
			return this.buffer.substr(this.pos, n);
		}
		*parseNext(next) {
			switch (next) {
				case "stream": return yield* this.parseStream();
				case "line-start": return yield* this.parseLineStart();
				case "block-start": return yield* this.parseBlockStart();
				case "doc": return yield* this.parseDocument();
				case "flow": return yield* this.parseFlowCollection();
				case "quoted-scalar": return yield* this.parseQuotedScalar();
				case "block-scalar": return yield* this.parseBlockScalar();
				case "plain-scalar": return yield* this.parsePlainScalar();
			}
		}
		*parseStream() {
			let line = this.getLine();
			if (line === null) return this.setNext("stream");
			if (line[0] === cst.BOM) {
				yield* this.pushCount(1);
				line = line.substring(1);
			}
			if (line[0] === "%") {
				let dirEnd = line.length;
				let cs = line.indexOf("#");
				while (cs !== -1) {
					const ch = line[cs - 1];
					if (ch === " " || ch === "	") {
						dirEnd = cs - 1;
						break;
					} else cs = line.indexOf("#", cs + 1);
				}
				while (true) {
					const ch = line[dirEnd - 1];
					if (ch === " " || ch === "	") dirEnd -= 1;
					else break;
				}
				const n = (yield* this.pushCount(dirEnd)) + (yield* this.pushSpaces(true));
				yield* this.pushCount(line.length - n);
				this.pushNewline();
				return "stream";
			}
			if (this.atLineEnd()) {
				const sp = yield* this.pushSpaces(true);
				yield* this.pushCount(line.length - sp);
				yield* this.pushNewline();
				return "stream";
			}
			yield cst.DOCUMENT;
			return yield* this.parseLineStart();
		}
		*parseLineStart() {
			const ch = this.charAt(0);
			if (!ch && !this.atEnd) return this.setNext("line-start");
			if (ch === "-" || ch === ".") {
				if (!this.atEnd && !this.hasChars(4)) return this.setNext("line-start");
				const s = this.peek(3);
				if ((s === "---" || s === "...") && isEmpty(this.charAt(3))) {
					yield* this.pushCount(3);
					this.indentValue = 0;
					this.indentNext = 0;
					return s === "---" ? "doc" : "stream";
				}
			}
			this.indentValue = yield* this.pushSpaces(false);
			if (this.indentNext > this.indentValue && !isEmpty(this.charAt(1))) this.indentNext = this.indentValue;
			return yield* this.parseBlockStart();
		}
		*parseBlockStart() {
			const [ch0, ch1] = this.peek(2);
			if (!ch1 && !this.atEnd) return this.setNext("block-start");
			if ((ch0 === "-" || ch0 === "?" || ch0 === ":") && isEmpty(ch1)) {
				const n = (yield* this.pushCount(1)) + (yield* this.pushSpaces(true));
				this.indentNext = this.indentValue + 1;
				this.indentValue += n;
				return "block-start";
			}
			return "doc";
		}
		*parseDocument() {
			yield* this.pushSpaces(true);
			const line = this.getLine();
			if (line === null) return this.setNext("doc");
			let n = yield* this.pushIndicators();
			switch (line[n]) {
				case "#": yield* this.pushCount(line.length - n);
				case void 0:
					yield* this.pushNewline();
					return yield* this.parseLineStart();
				case "{":
				case "[":
					yield* this.pushCount(1);
					this.flowKey = false;
					this.flowLevel = 1;
					return "flow";
				case "}":
				case "]":
					yield* this.pushCount(1);
					return "doc";
				case "*":
					yield* this.pushUntil(isNotAnchorChar);
					return "doc";
				case "\"":
				case "'": return yield* this.parseQuotedScalar();
				case "|":
				case ">":
					n += yield* this.parseBlockScalarHeader();
					n += yield* this.pushSpaces(true);
					yield* this.pushCount(line.length - n);
					yield* this.pushNewline();
					return yield* this.parseBlockScalar();
				default: return yield* this.parsePlainScalar();
			}
		}
		*parseFlowCollection() {
			let nl, sp;
			let indent = -1;
			do {
				nl = yield* this.pushNewline();
				if (nl > 0) {
					sp = yield* this.pushSpaces(false);
					this.indentValue = indent = sp;
				} else sp = 0;
				sp += yield* this.pushSpaces(true);
			} while (nl + sp > 0);
			const line = this.getLine();
			if (line === null) return this.setNext("flow");
			if (indent !== -1 && indent < this.indentNext && line[0] !== "#" || indent === 0 && (line.startsWith("---") || line.startsWith("...")) && isEmpty(line[3])) {
				if (!(indent === this.indentNext - 1 && this.flowLevel === 1 && (line[0] === "]" || line[0] === "}"))) {
					this.flowLevel = 0;
					yield cst.FLOW_END;
					return yield* this.parseLineStart();
				}
			}
			let n = 0;
			while (line[n] === ",") {
				n += yield* this.pushCount(1);
				n += yield* this.pushSpaces(true);
				this.flowKey = false;
			}
			n += yield* this.pushIndicators();
			switch (line[n]) {
				case void 0: return "flow";
				case "#":
					yield* this.pushCount(line.length - n);
					return "flow";
				case "{":
				case "[":
					yield* this.pushCount(1);
					this.flowKey = false;
					this.flowLevel += 1;
					return "flow";
				case "}":
				case "]":
					yield* this.pushCount(1);
					this.flowKey = true;
					this.flowLevel -= 1;
					return this.flowLevel ? "flow" : "doc";
				case "*":
					yield* this.pushUntil(isNotAnchorChar);
					return "flow";
				case "\"":
				case "'":
					this.flowKey = true;
					return yield* this.parseQuotedScalar();
				case ":": {
					const next = this.charAt(1);
					if (this.flowKey || isEmpty(next) || next === ",") {
						this.flowKey = false;
						yield* this.pushCount(1);
						yield* this.pushSpaces(true);
						return "flow";
					}
				}
				default:
					this.flowKey = false;
					return yield* this.parsePlainScalar();
			}
		}
		*parseQuotedScalar() {
			const quote = this.charAt(0);
			let end = this.buffer.indexOf(quote, this.pos + 1);
			if (quote === "'") while (end !== -1 && this.buffer[end + 1] === "'") end = this.buffer.indexOf("'", end + 2);
			else while (end !== -1) {
				let n = 0;
				while (this.buffer[end - 1 - n] === "\\") n += 1;
				if (n % 2 === 0) break;
				end = this.buffer.indexOf("\"", end + 1);
			}
			const qb = this.buffer.substring(0, end);
			let nl = qb.indexOf("\n", this.pos);
			if (nl !== -1) {
				while (nl !== -1) {
					const cs = this.continueScalar(nl + 1);
					if (cs === -1) break;
					nl = qb.indexOf("\n", cs);
				}
				if (nl !== -1) end = nl - (qb[nl - 1] === "\r" ? 2 : 1);
			}
			if (end === -1) {
				if (!this.atEnd) return this.setNext("quoted-scalar");
				end = this.buffer.length;
			}
			yield* this.pushToIndex(end + 1, false);
			return this.flowLevel ? "flow" : "doc";
		}
		*parseBlockScalarHeader() {
			this.blockScalarIndent = -1;
			this.blockScalarKeep = false;
			let i = this.pos;
			while (true) {
				const ch = this.buffer[++i];
				if (ch === "+") this.blockScalarKeep = true;
				else if (ch > "0" && ch <= "9") this.blockScalarIndent = Number(ch) - 1;
				else if (ch !== "-") break;
			}
			return yield* this.pushUntil((ch) => isEmpty(ch) || ch === "#");
		}
		*parseBlockScalar() {
			let nl = this.pos - 1;
			let indent = 0;
			let ch;
			loop: for (let i = this.pos; ch = this.buffer[i]; ++i) switch (ch) {
				case " ":
					indent += 1;
					break;
				case "\n":
					nl = i;
					indent = 0;
					break;
				case "\r": {
					const next = this.buffer[i + 1];
					if (!next && !this.atEnd) return this.setNext("block-scalar");
					if (next === "\n") break;
				}
				default: break loop;
			}
			if (!ch && !this.atEnd) return this.setNext("block-scalar");
			if (indent >= this.indentNext) {
				if (this.blockScalarIndent === -1) this.indentNext = indent;
				else this.indentNext = this.blockScalarIndent + (this.indentNext === 0 ? 1 : this.indentNext);
				do {
					const cs = this.continueScalar(nl + 1);
					if (cs === -1) break;
					nl = this.buffer.indexOf("\n", cs);
				} while (nl !== -1);
				if (nl === -1) {
					if (!this.atEnd) return this.setNext("block-scalar");
					nl = this.buffer.length;
				}
			}
			let i = nl + 1;
			ch = this.buffer[i];
			while (ch === " ") ch = this.buffer[++i];
			if (ch === "	") {
				while (ch === "	" || ch === " " || ch === "\r" || ch === "\n") ch = this.buffer[++i];
				nl = i - 1;
			} else if (!this.blockScalarKeep) do {
				let i = nl - 1;
				let ch = this.buffer[i];
				if (ch === "\r") ch = this.buffer[--i];
				const lastChar = i;
				while (ch === " ") ch = this.buffer[--i];
				if (ch === "\n" && i >= this.pos && i + 1 + indent > lastChar) nl = i;
				else break;
			} while (true);
			yield cst.SCALAR;
			yield* this.pushToIndex(nl + 1, true);
			return yield* this.parseLineStart();
		}
		*parsePlainScalar() {
			const inFlow = this.flowLevel > 0;
			let end = this.pos - 1;
			let i = this.pos - 1;
			let ch;
			while (ch = this.buffer[++i]) if (ch === ":") {
				const next = this.buffer[i + 1];
				if (isEmpty(next) || inFlow && flowIndicatorChars.has(next)) break;
				end = i;
			} else if (isEmpty(ch)) {
				let next = this.buffer[i + 1];
				if (ch === "\r") {
					if (next === "\n") {
						i += 1;
						ch = "\n";
						next = this.buffer[i + 1];
					} else end = i;
				}
				if (next === "#" || inFlow && flowIndicatorChars.has(next)) break;
				if (ch === "\n") {
					const cs = this.continueScalar(i + 1);
					if (cs === -1) break;
					i = Math.max(i, cs - 2);
				}
			} else {
				if (inFlow && flowIndicatorChars.has(ch)) break;
				end = i;
			}
			if (!ch && !this.atEnd) return this.setNext("plain-scalar");
			yield cst.SCALAR;
			yield* this.pushToIndex(end + 1, true);
			return inFlow ? "flow" : "doc";
		}
		*pushCount(n) {
			if (n > 0) {
				yield this.buffer.substr(this.pos, n);
				this.pos += n;
				return n;
			}
			return 0;
		}
		*pushToIndex(i, allowEmpty) {
			const s = this.buffer.slice(this.pos, i);
			if (s) {
				yield s;
				this.pos += s.length;
				return s.length;
			} else if (allowEmpty) yield "";
			return 0;
		}
		*pushIndicators() {
			let n = 0;
			loop: while (true) {
				switch (this.charAt(0)) {
					case "!":
						n += yield* this.pushTag();
						n += yield* this.pushSpaces(true);
						continue loop;
					case "&":
						n += yield* this.pushUntil(isNotAnchorChar);
						n += yield* this.pushSpaces(true);
						continue loop;
					case "-":
					case "?":
					case ":": {
						const inFlow = this.flowLevel > 0;
						const ch1 = this.charAt(1);
						if (isEmpty(ch1) || inFlow && flowIndicatorChars.has(ch1)) {
							if (!inFlow) this.indentNext = this.indentValue + 1;
							else if (this.flowKey) this.flowKey = false;
							n += yield* this.pushCount(1);
							n += yield* this.pushSpaces(true);
							continue loop;
						}
					}
				}
				break loop;
			}
			return n;
		}
		*pushTag() {
			if (this.charAt(1) === "<") {
				let i = this.pos + 2;
				let ch = this.buffer[i];
				while (!isEmpty(ch) && ch !== ">") ch = this.buffer[++i];
				return yield* this.pushToIndex(ch === ">" ? i + 1 : i, false);
			} else {
				let i = this.pos + 1;
				let ch = this.buffer[i];
				while (ch) if (tagChars.has(ch)) ch = this.buffer[++i];
				else if (ch === "%" && hexDigits.has(this.buffer[i + 1]) && hexDigits.has(this.buffer[i + 2])) ch = this.buffer[i += 3];
				else break;
				return yield* this.pushToIndex(i, false);
			}
		}
		*pushNewline() {
			const ch = this.buffer[this.pos];
			if (ch === "\n") return yield* this.pushCount(1);
			else if (ch === "\r" && this.charAt(1) === "\n") return yield* this.pushCount(2);
			else return 0;
		}
		*pushSpaces(allowTabs) {
			let i = this.pos - 1;
			let ch;
			do
				ch = this.buffer[++i];
			while (ch === " " || allowTabs && ch === "	");
			const n = i - this.pos;
			if (n > 0) {
				yield this.buffer.substr(this.pos, n);
				this.pos = i;
			}
			return n;
		}
		*pushUntil(test) {
			let i = this.pos;
			let ch = this.buffer[i];
			while (!test(ch)) ch = this.buffer[++i];
			return yield* this.pushToIndex(i, false);
		}
	};
	exports.Lexer = Lexer;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/line-counter.js
var require_line_counter = /* @__PURE__ */ __commonJSMin(((exports) => {
	/**
	* Tracks newlines during parsing in order to provide an efficient API for
	* determining the one-indexed `{ line, col }` position for any offset
	* within the input.
	*/
	var LineCounter = class {
		constructor() {
			this.lineStarts = [];
			/**
			* Should be called in ascending order. Otherwise, call
			* `lineCounter.lineStarts.sort()` before calling `linePos()`.
			*/
			this.addNewLine = (offset) => this.lineStarts.push(offset);
			/**
			* Performs a binary search and returns the 1-indexed { line, col }
			* position of `offset`. If `line === 0`, `addNewLine` has never been
			* called or `offset` is before the first known newline.
			*/
			this.linePos = (offset) => {
				let low = 0;
				let high = this.lineStarts.length;
				while (low < high) {
					const mid = low + high >> 1;
					if (this.lineStarts[mid] < offset) low = mid + 1;
					else high = mid;
				}
				if (this.lineStarts[low] === offset) return {
					line: low + 1,
					col: 1
				};
				if (low === 0) return {
					line: 0,
					col: offset
				};
				const start = this.lineStarts[low - 1];
				return {
					line: low,
					col: offset - start + 1
				};
			};
		}
	};
	exports.LineCounter = LineCounter;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/parse/parser.js
var require_parser = /* @__PURE__ */ __commonJSMin(((exports) => {
	var node_process = __require("process");
	var cst = require_cst();
	var lexer = require_lexer();
	function includesToken(list, type) {
		for (let i = 0; i < list.length; ++i) if (list[i].type === type) return true;
		return false;
	}
	function findNonEmptyIndex(list) {
		for (let i = 0; i < list.length; ++i) switch (list[i].type) {
			case "space":
			case "comment":
			case "newline": break;
			default: return i;
		}
		return -1;
	}
	function isFlowToken(token) {
		switch (token?.type) {
			case "alias":
			case "scalar":
			case "single-quoted-scalar":
			case "double-quoted-scalar":
			case "flow-collection": return true;
			default: return false;
		}
	}
	function getPrevProps(parent) {
		switch (parent.type) {
			case "document": return parent.start;
			case "block-map": {
				const it = parent.items[parent.items.length - 1];
				return it.sep ?? it.start;
			}
			case "block-seq": return parent.items[parent.items.length - 1].start;
			/* istanbul ignore next should not happen */
			default: return [];
		}
	}
	/** Note: May modify input array */
	function getFirstKeyStartProps(prev) {
		if (prev.length === 0) return [];
		let i = prev.length;
		loop: while (--i >= 0) switch (prev[i].type) {
			case "doc-start":
			case "explicit-key-ind":
			case "map-value-ind":
			case "seq-item-ind":
			case "newline": break loop;
		}
		while (prev[++i]?.type === "space");
		return prev.splice(i, prev.length);
	}
	function arrayPushArray(target, source) {
		if (source.length < 1e5) Array.prototype.push.apply(target, source);
		else for (let i = 0; i < source.length; ++i) target.push(source[i]);
	}
	function fixFlowSeqItems(fc) {
		if (fc.start.type === "flow-seq-start") {
			for (const it of fc.items) if (it.sep && !it.value && !includesToken(it.start, "explicit-key-ind") && !includesToken(it.sep, "map-value-ind")) {
				if (it.key) it.value = it.key;
				delete it.key;
				if (isFlowToken(it.value)) {
					if (it.value.end) arrayPushArray(it.value.end, it.sep);
					else it.value.end = it.sep;
				} else arrayPushArray(it.start, it.sep);
				delete it.sep;
			}
		}
	}
	/**
	* A YAML concrete syntax tree (CST) parser
	*
	* ```ts
	* const src: string = ...
	* for (const token of new Parser().parse(src)) {
	*   // token: Token
	* }
	* ```
	*
	* To use the parser with a user-provided lexer:
	*
	* ```ts
	* function* parse(source: string, lexer: Lexer) {
	*   const parser = new Parser()
	*   for (const lexeme of lexer.lex(source))
	*     yield* parser.next(lexeme)
	*   yield* parser.end()
	* }
	*
	* const src: string = ...
	* const lexer = new Lexer()
	* for (const token of parse(src, lexer)) {
	*   // token: Token
	* }
	* ```
	*/
	var Parser = class {
		/**
		* @param onNewLine - If defined, called separately with the start position of
		*   each new line (in `parse()`, including the start of input).
		*/
		constructor(onNewLine) {
			/** If true, space and sequence indicators count as indentation */
			this.atNewLine = true;
			/** If true, next token is a scalar value */
			this.atScalar = false;
			/** Current indentation level */
			this.indent = 0;
			/** Current offset since the start of parsing */
			this.offset = 0;
			/** On the same line with a block map key */
			this.onKeyLine = false;
			/** Top indicates the node that's currently being built */
			this.stack = [];
			/** The source of the current token, set in parse() */
			this.source = "";
			/** The type of the current token, set in parse() */
			this.type = "";
			this.lexer = new lexer.Lexer();
			this.onNewLine = onNewLine;
		}
		/**
		* Parse `source` as a YAML stream.
		* If `incomplete`, a part of the last line may be left as a buffer for the next call.
		*
		* Errors are not thrown, but yielded as `{ type: 'error', message }` tokens.
		*
		* @returns A generator of tokens representing each directive, document, and other structure.
		*/
		*parse(source, incomplete = false) {
			if (this.onNewLine && this.offset === 0) this.onNewLine(0);
			for (const lexeme of this.lexer.lex(source, incomplete)) yield* this.next(lexeme);
			if (!incomplete) yield* this.end();
		}
		/**
		* Advance the parser by the `source` of one lexical token.
		*/
		*next(source) {
			this.source = source;
			if (node_process.env.LOG_TOKENS) console.log("|", cst.prettyToken(source));
			if (this.atScalar) {
				this.atScalar = false;
				yield* this.step();
				this.offset += source.length;
				return;
			}
			const type = cst.tokenType(source);
			if (!type) {
				const message = `Not a YAML token: ${source}`;
				yield* this.pop({
					type: "error",
					offset: this.offset,
					message,
					source
				});
				this.offset += source.length;
			} else if (type === "scalar") {
				this.atNewLine = false;
				this.atScalar = true;
				this.type = "scalar";
			} else {
				this.type = type;
				yield* this.step();
				switch (type) {
					case "newline":
						this.atNewLine = true;
						this.indent = 0;
						if (this.onNewLine) this.onNewLine(this.offset + source.length);
						break;
					case "space":
						if (this.atNewLine && source[0] === " ") this.indent += source.length;
						break;
					case "explicit-key-ind":
					case "map-value-ind":
					case "seq-item-ind":
						if (this.atNewLine) this.indent += source.length;
						break;
					case "doc-mode":
					case "flow-error-end": return;
					default: this.atNewLine = false;
				}
				this.offset += source.length;
			}
		}
		/** Call at end of input to push out any remaining constructions */
		*end() {
			while (this.stack.length > 0) yield* this.pop();
		}
		get sourceToken() {
			return {
				type: this.type,
				offset: this.offset,
				indent: this.indent,
				source: this.source
			};
		}
		*step() {
			const top = this.peek(1);
			if (this.type === "doc-end" && top?.type !== "doc-end") {
				while (this.stack.length > 0) yield* this.pop();
				this.stack.push({
					type: "doc-end",
					offset: this.offset,
					source: this.source
				});
				return;
			}
			if (!top) return yield* this.stream();
			switch (top.type) {
				case "document": return yield* this.document(top);
				case "alias":
				case "scalar":
				case "single-quoted-scalar":
				case "double-quoted-scalar": return yield* this.scalar(top);
				case "block-scalar": return yield* this.blockScalar(top);
				case "block-map": return yield* this.blockMap(top);
				case "block-seq": return yield* this.blockSequence(top);
				case "flow-collection": return yield* this.flowCollection(top);
				case "doc-end": return yield* this.documentEnd(top);
			}
			/* istanbul ignore next should not happen */
			yield* this.pop();
		}
		peek(n) {
			return this.stack[this.stack.length - n];
		}
		*pop(error) {
			const token = error ?? this.stack.pop();
			/* istanbul ignore if should not happen */
			if (!token) yield {
				type: "error",
				offset: this.offset,
				source: "",
				message: "Tried to pop an empty stack"
			};
			else if (this.stack.length === 0) yield token;
			else {
				const top = this.peek(1);
				if (token.type === "block-scalar") token.indent = "indent" in top ? top.indent : 0;
				else if (token.type === "flow-collection" && top.type === "document") token.indent = 0;
				if (token.type === "flow-collection") fixFlowSeqItems(token);
				switch (top.type) {
					case "document":
						top.value = token;
						break;
					case "block-scalar":
						top.props.push(token);
						break;
					case "block-map": {
						const it = top.items[top.items.length - 1];
						if (it.value) {
							top.items.push({
								start: [],
								key: token,
								sep: []
							});
							this.onKeyLine = true;
							return;
						} else if (it.sep) it.value = token;
						else {
							Object.assign(it, {
								key: token,
								sep: []
							});
							this.onKeyLine = !it.explicitKey;
							return;
						}
						break;
					}
					case "block-seq": {
						const it = top.items[top.items.length - 1];
						if (it.value) top.items.push({
							start: [],
							value: token
						});
						else it.value = token;
						break;
					}
					case "flow-collection": {
						const it = top.items[top.items.length - 1];
						if (!it || it.value) top.items.push({
							start: [],
							key: token,
							sep: []
						});
						else if (it.sep) it.value = token;
						else Object.assign(it, {
							key: token,
							sep: []
						});
						return;
					}
					/* istanbul ignore next should not happen */
					default:
						yield* this.pop();
						yield* this.pop(token);
				}
				if ((top.type === "document" || top.type === "block-map" || top.type === "block-seq") && (token.type === "block-map" || token.type === "block-seq")) {
					const last = token.items[token.items.length - 1];
					if (last && !last.sep && !last.value && last.start.length > 0 && findNonEmptyIndex(last.start) === -1 && (token.indent === 0 || last.start.every((st) => st.type !== "comment" || st.indent < token.indent))) {
						if (top.type === "document") top.end = last.start;
						else top.items.push({ start: last.start });
						token.items.splice(-1, 1);
					}
				}
			}
		}
		*stream() {
			switch (this.type) {
				case "directive-line":
					yield {
						type: "directive",
						offset: this.offset,
						source: this.source
					};
					return;
				case "byte-order-mark":
				case "space":
				case "comment":
				case "newline":
					yield this.sourceToken;
					return;
				case "doc-mode":
				case "doc-start": {
					const doc = {
						type: "document",
						offset: this.offset,
						start: []
					};
					if (this.type === "doc-start") doc.start.push(this.sourceToken);
					this.stack.push(doc);
					return;
				}
			}
			yield {
				type: "error",
				offset: this.offset,
				message: `Unexpected ${this.type} token in YAML stream`,
				source: this.source
			};
		}
		*document(doc) {
			if (doc.value) return yield* this.lineEnd(doc);
			switch (this.type) {
				case "doc-start":
					if (findNonEmptyIndex(doc.start) !== -1) {
						yield* this.pop();
						yield* this.step();
					} else doc.start.push(this.sourceToken);
					return;
				case "anchor":
				case "tag":
				case "space":
				case "comment":
				case "newline":
					doc.start.push(this.sourceToken);
					return;
			}
			const bv = this.startBlockValue(doc);
			if (bv) this.stack.push(bv);
			else yield {
				type: "error",
				offset: this.offset,
				message: `Unexpected ${this.type} token in YAML document`,
				source: this.source
			};
		}
		*scalar(scalar) {
			if (this.type === "map-value-ind") {
				const start = getFirstKeyStartProps(getPrevProps(this.peek(2)));
				let sep;
				if (scalar.end) {
					sep = scalar.end;
					sep.push(this.sourceToken);
					delete scalar.end;
				} else sep = [this.sourceToken];
				const map = {
					type: "block-map",
					offset: scalar.offset,
					indent: scalar.indent,
					items: [{
						start,
						key: scalar,
						sep
					}]
				};
				this.onKeyLine = true;
				this.stack[this.stack.length - 1] = map;
			} else yield* this.lineEnd(scalar);
		}
		*blockScalar(scalar) {
			switch (this.type) {
				case "space":
				case "comment":
				case "newline":
					scalar.props.push(this.sourceToken);
					return;
				case "scalar":
					scalar.source = this.source;
					this.atNewLine = true;
					this.indent = 0;
					if (this.onNewLine) {
						let nl = this.source.indexOf("\n") + 1;
						while (nl !== 0) {
							this.onNewLine(this.offset + nl);
							nl = this.source.indexOf("\n", nl) + 1;
						}
					}
					yield* this.pop();
					break;
				/* istanbul ignore next should not happen */
				default:
					yield* this.pop();
					yield* this.step();
			}
		}
		*blockMap(map) {
			const it = map.items[map.items.length - 1];
			switch (this.type) {
				case "newline":
					this.onKeyLine = false;
					if (it.value) {
						const end = "end" in it.value ? it.value.end : void 0;
						if ((Array.isArray(end) ? end[end.length - 1] : void 0)?.type === "comment") end?.push(this.sourceToken);
						else map.items.push({ start: [this.sourceToken] });
					} else if (it.sep) it.sep.push(this.sourceToken);
					else it.start.push(this.sourceToken);
					return;
				case "space":
				case "comment":
					if (it.value) map.items.push({ start: [this.sourceToken] });
					else if (it.sep) it.sep.push(this.sourceToken);
					else {
						if (this.atIndentedComment(it.start, map.indent)) {
							const end = map.items[map.items.length - 2]?.value?.end;
							if (Array.isArray(end)) {
								arrayPushArray(end, it.start);
								end.push(this.sourceToken);
								map.items.pop();
								return;
							}
						}
						it.start.push(this.sourceToken);
					}
					return;
			}
			if (this.indent >= map.indent) {
				const atMapIndent = !this.onKeyLine && this.indent === map.indent;
				const atNextItem = atMapIndent && (it.sep || it.explicitKey) && this.type !== "seq-item-ind";
				let start = [];
				if (atNextItem && it.sep && !it.value) {
					const nl = [];
					for (let i = 0; i < it.sep.length; ++i) {
						const st = it.sep[i];
						switch (st.type) {
							case "newline":
								nl.push(i);
								break;
							case "space": break;
							case "comment":
								if (st.indent > map.indent) nl.length = 0;
								break;
							default: nl.length = 0;
						}
					}
					if (nl.length >= 2) start = it.sep.splice(nl[1]);
				}
				switch (this.type) {
					case "anchor":
					case "tag":
						if (atNextItem || it.value) {
							start.push(this.sourceToken);
							map.items.push({ start });
							this.onKeyLine = true;
						} else if (it.sep) it.sep.push(this.sourceToken);
						else it.start.push(this.sourceToken);
						return;
					case "explicit-key-ind":
						if (!it.sep && !it.explicitKey) {
							it.start.push(this.sourceToken);
							it.explicitKey = true;
						} else if (atNextItem || it.value) {
							start.push(this.sourceToken);
							map.items.push({
								start,
								explicitKey: true
							});
						} else this.stack.push({
							type: "block-map",
							offset: this.offset,
							indent: this.indent,
							items: [{
								start: [this.sourceToken],
								explicitKey: true
							}]
						});
						this.onKeyLine = true;
						return;
					case "map-value-ind":
						if (it.explicitKey) {
							if (!it.sep) {
								if (includesToken(it.start, "newline")) Object.assign(it, {
									key: null,
									sep: [this.sourceToken]
								});
								else {
									const start = getFirstKeyStartProps(it.start);
									this.stack.push({
										type: "block-map",
										offset: this.offset,
										indent: this.indent,
										items: [{
											start,
											key: null,
											sep: [this.sourceToken]
										}]
									});
								}
							} else if (it.value) map.items.push({
								start: [],
								key: null,
								sep: [this.sourceToken]
							});
							else if (includesToken(it.sep, "map-value-ind")) this.stack.push({
								type: "block-map",
								offset: this.offset,
								indent: this.indent,
								items: [{
									start,
									key: null,
									sep: [this.sourceToken]
								}]
							});
							else if (isFlowToken(it.key) && !includesToken(it.sep, "newline")) {
								const start = getFirstKeyStartProps(it.start);
								const key = it.key;
								const sep = it.sep;
								sep.push(this.sourceToken);
								delete it.key;
								delete it.sep;
								this.stack.push({
									type: "block-map",
									offset: this.offset,
									indent: this.indent,
									items: [{
										start,
										key,
										sep
									}]
								});
							} else if (start.length > 0) it.sep = it.sep.concat(start, this.sourceToken);
							else it.sep.push(this.sourceToken);
						} else if (!it.sep) Object.assign(it, {
							key: null,
							sep: [this.sourceToken]
						});
						else if (it.value || atNextItem) map.items.push({
							start,
							key: null,
							sep: [this.sourceToken]
						});
						else if (includesToken(it.sep, "map-value-ind")) this.stack.push({
							type: "block-map",
							offset: this.offset,
							indent: this.indent,
							items: [{
								start: [],
								key: null,
								sep: [this.sourceToken]
							}]
						});
						else it.sep.push(this.sourceToken);
						this.onKeyLine = true;
						return;
					case "alias":
					case "scalar":
					case "single-quoted-scalar":
					case "double-quoted-scalar": {
						const fs = this.flowScalar(this.type);
						if (atNextItem || it.value) {
							map.items.push({
								start,
								key: fs,
								sep: []
							});
							this.onKeyLine = true;
						} else if (it.sep) this.stack.push(fs);
						else {
							Object.assign(it, {
								key: fs,
								sep: []
							});
							this.onKeyLine = true;
						}
						return;
					}
					default: {
						const bv = this.startBlockValue(map);
						if (bv) {
							if (bv.type === "block-seq") {
								if (!it.explicitKey && it.sep && !includesToken(it.sep, "newline")) {
									yield* this.pop({
										type: "error",
										offset: this.offset,
										message: "Unexpected block-seq-ind on same line with key",
										source: this.source
									});
									return;
								}
							} else if (atMapIndent) map.items.push({ start });
							this.stack.push(bv);
							return;
						}
					}
				}
			}
			yield* this.pop();
			yield* this.step();
		}
		*blockSequence(seq) {
			const it = seq.items[seq.items.length - 1];
			switch (this.type) {
				case "newline":
					if (it.value) {
						const end = "end" in it.value ? it.value.end : void 0;
						if ((Array.isArray(end) ? end[end.length - 1] : void 0)?.type === "comment") end?.push(this.sourceToken);
						else seq.items.push({ start: [this.sourceToken] });
					} else it.start.push(this.sourceToken);
					return;
				case "space":
				case "comment":
					if (it.value) seq.items.push({ start: [this.sourceToken] });
					else {
						if (this.atIndentedComment(it.start, seq.indent)) {
							const end = seq.items[seq.items.length - 2]?.value?.end;
							if (Array.isArray(end)) {
								arrayPushArray(end, it.start);
								end.push(this.sourceToken);
								seq.items.pop();
								return;
							}
						}
						it.start.push(this.sourceToken);
					}
					return;
				case "anchor":
				case "tag":
					if (it.value || this.indent <= seq.indent) break;
					it.start.push(this.sourceToken);
					return;
				case "seq-item-ind":
					if (this.indent !== seq.indent) break;
					if (it.value || includesToken(it.start, "seq-item-ind")) seq.items.push({ start: [this.sourceToken] });
					else it.start.push(this.sourceToken);
					return;
			}
			if (this.indent > seq.indent) {
				const bv = this.startBlockValue(seq);
				if (bv) {
					this.stack.push(bv);
					return;
				}
			}
			yield* this.pop();
			yield* this.step();
		}
		*flowCollection(fc) {
			const it = fc.items[fc.items.length - 1];
			if (this.type === "flow-error-end") {
				let top;
				do {
					yield* this.pop();
					top = this.peek(1);
				} while (top?.type === "flow-collection");
			} else if (fc.end.length === 0) {
				switch (this.type) {
					case "comma":
					case "explicit-key-ind":
						if (!it || it.sep) fc.items.push({ start: [this.sourceToken] });
						else it.start.push(this.sourceToken);
						return;
					case "map-value-ind":
						if (!it || it.value) fc.items.push({
							start: [],
							key: null,
							sep: [this.sourceToken]
						});
						else if (it.sep) it.sep.push(this.sourceToken);
						else Object.assign(it, {
							key: null,
							sep: [this.sourceToken]
						});
						return;
					case "space":
					case "comment":
					case "newline":
					case "anchor":
					case "tag":
						if (!it || it.value) fc.items.push({ start: [this.sourceToken] });
						else if (it.sep) it.sep.push(this.sourceToken);
						else it.start.push(this.sourceToken);
						return;
					case "alias":
					case "scalar":
					case "single-quoted-scalar":
					case "double-quoted-scalar": {
						const fs = this.flowScalar(this.type);
						if (!it || it.value) fc.items.push({
							start: [],
							key: fs,
							sep: []
						});
						else if (it.sep) this.stack.push(fs);
						else Object.assign(it, {
							key: fs,
							sep: []
						});
						return;
					}
					case "flow-map-end":
					case "flow-seq-end":
						fc.end.push(this.sourceToken);
						return;
				}
				const bv = this.startBlockValue(fc);
				/* istanbul ignore else should not happen */
				if (bv) this.stack.push(bv);
				else {
					yield* this.pop();
					yield* this.step();
				}
			} else {
				const parent = this.peek(2);
				if (parent.type === "block-map" && (this.type === "map-value-ind" && parent.indent === fc.indent || this.type === "newline" && !parent.items[parent.items.length - 1].sep)) {
					yield* this.pop();
					yield* this.step();
				} else if (this.type === "map-value-ind" && parent.type !== "flow-collection") {
					const start = getFirstKeyStartProps(getPrevProps(parent));
					fixFlowSeqItems(fc);
					const sep = fc.end.splice(1, fc.end.length);
					sep.push(this.sourceToken);
					const map = {
						type: "block-map",
						offset: fc.offset,
						indent: fc.indent,
						items: [{
							start,
							key: fc,
							sep
						}]
					};
					this.onKeyLine = true;
					this.stack[this.stack.length - 1] = map;
				} else yield* this.lineEnd(fc);
			}
		}
		flowScalar(type) {
			if (this.onNewLine) {
				let nl = this.source.indexOf("\n") + 1;
				while (nl !== 0) {
					this.onNewLine(this.offset + nl);
					nl = this.source.indexOf("\n", nl) + 1;
				}
			}
			return {
				type,
				offset: this.offset,
				indent: this.indent,
				source: this.source
			};
		}
		startBlockValue(parent) {
			switch (this.type) {
				case "alias":
				case "scalar":
				case "single-quoted-scalar":
				case "double-quoted-scalar": return this.flowScalar(this.type);
				case "block-scalar-header": return {
					type: "block-scalar",
					offset: this.offset,
					indent: this.indent,
					props: [this.sourceToken],
					source: ""
				};
				case "flow-map-start":
				case "flow-seq-start": return {
					type: "flow-collection",
					offset: this.offset,
					indent: this.indent,
					start: this.sourceToken,
					items: [],
					end: []
				};
				case "seq-item-ind": return {
					type: "block-seq",
					offset: this.offset,
					indent: this.indent,
					items: [{ start: [this.sourceToken] }]
				};
				case "explicit-key-ind": {
					this.onKeyLine = true;
					const start = getFirstKeyStartProps(getPrevProps(parent));
					start.push(this.sourceToken);
					return {
						type: "block-map",
						offset: this.offset,
						indent: this.indent,
						items: [{
							start,
							explicitKey: true
						}]
					};
				}
				case "map-value-ind": {
					this.onKeyLine = true;
					const start = getFirstKeyStartProps(getPrevProps(parent));
					return {
						type: "block-map",
						offset: this.offset,
						indent: this.indent,
						items: [{
							start,
							key: null,
							sep: [this.sourceToken]
						}]
					};
				}
			}
			return null;
		}
		atIndentedComment(start, indent) {
			if (this.type !== "comment") return false;
			if (this.indent <= indent) return false;
			return start.every((st) => st.type === "newline" || st.type === "space");
		}
		*documentEnd(docEnd) {
			if (this.type !== "doc-mode") {
				if (docEnd.end) docEnd.end.push(this.sourceToken);
				else docEnd.end = [this.sourceToken];
				if (this.type === "newline") yield* this.pop();
			}
		}
		*lineEnd(token) {
			switch (this.type) {
				case "comma":
				case "doc-start":
				case "doc-end":
				case "flow-seq-end":
				case "flow-map-end":
				case "map-value-ind":
					yield* this.pop();
					yield* this.step();
					break;
				case "newline": this.onKeyLine = false;
				default:
					if (token.end) token.end.push(this.sourceToken);
					else token.end = [this.sourceToken];
					if (this.type === "newline") yield* this.pop();
			}
		}
	};
	exports.Parser = Parser;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/public-api.js
var require_public_api = /* @__PURE__ */ __commonJSMin(((exports) => {
	var composer = require_composer();
	var Document = require_Document();
	var errors = require_errors();
	var log = require_log();
	var identity = require_identity();
	var lineCounter = require_line_counter();
	var parser = require_parser();
	function parseOptions(options) {
		const prettyErrors = options.prettyErrors !== false;
		return {
			lineCounter: options.lineCounter || prettyErrors && new lineCounter.LineCounter() || null,
			prettyErrors
		};
	}
	/**
	* Parse the input as a stream of YAML documents.
	*
	* Documents should be separated from each other by `...` or `---` marker lines.
	*
	* @returns If an empty `docs` array is returned, it will be of type
	*   EmptyStream and contain additional stream information. In
	*   TypeScript, you should use `'empty' in docs` as a type guard for it.
	*/
	function parseAllDocuments(source, options = {}) {
		const { lineCounter, prettyErrors } = parseOptions(options);
		const parser$1 = new parser.Parser(lineCounter?.addNewLine);
		const composer$1 = new composer.Composer(options);
		const docs = Array.from(composer$1.compose(parser$1.parse(source)));
		if (prettyErrors && lineCounter) for (const doc of docs) {
			doc.errors.forEach(errors.prettifyError(source, lineCounter));
			doc.warnings.forEach(errors.prettifyError(source, lineCounter));
		}
		if (docs.length > 0) return docs;
		return Object.assign([], { empty: true }, composer$1.streamInfo());
	}
	/** Parse an input string into a single YAML.Document */
	function parseDocument(source, options = {}) {
		const { lineCounter, prettyErrors } = parseOptions(options);
		const parser$1 = new parser.Parser(lineCounter?.addNewLine);
		const composer$1 = new composer.Composer(options);
		let doc = null;
		for (const _doc of composer$1.compose(parser$1.parse(source), true, source.length)) if (!doc) doc = _doc;
		else if (doc.options.logLevel !== "silent") {
			doc.errors.push(new errors.YAMLParseError(_doc.range.slice(0, 2), "MULTIPLE_DOCS", "Source contains multiple documents; please use YAML.parseAllDocuments()"));
			break;
		}
		if (prettyErrors && lineCounter) {
			doc.errors.forEach(errors.prettifyError(source, lineCounter));
			doc.warnings.forEach(errors.prettifyError(source, lineCounter));
		}
		return doc;
	}
	function parse(src, reviver, options) {
		let _reviver = void 0;
		if (typeof reviver === "function") _reviver = reviver;
		else if (options === void 0 && reviver && typeof reviver === "object") options = reviver;
		const doc = parseDocument(src, options);
		if (!doc) return null;
		doc.warnings.forEach((warning) => log.warn(doc.options.logLevel, warning));
		if (doc.errors.length > 0) {
			if (doc.options.logLevel !== "silent") throw doc.errors[0];
			else doc.errors = [];
		}
		return doc.toJS(Object.assign({ reviver: _reviver }, options));
	}
	function stringify(value, replacer, options) {
		let _replacer = null;
		if (typeof replacer === "function" || Array.isArray(replacer)) _replacer = replacer;
		else if (options === void 0 && replacer) options = replacer;
		if (typeof options === "string") options = options.length;
		if (typeof options === "number") {
			const indent = Math.round(options);
			options = indent < 1 ? void 0 : indent > 8 ? { indent: 8 } : { indent };
		}
		if (value === void 0) {
			const { keepUndefined } = options ?? replacer ?? {};
			if (!keepUndefined) return void 0;
		}
		if (identity.isDocument(value) && !_replacer) return value.toString(options);
		return new Document.Document(value, _replacer, options).toString(options);
	}
	exports.parse = parse;
	exports.parseAllDocuments = parseAllDocuments;
	exports.parseDocument = parseDocument;
	exports.stringify = stringify;
}));
// ../node_modules/.pnpm/yaml@2.9.1/node_modules/yaml/dist/index.js
var require_dist = /* @__PURE__ */ __commonJSMin(((exports) => {
	var composer = require_composer();
	var Document = require_Document();
	var Schema = require_Schema();
	var errors = require_errors();
	var Alias = require_Alias();
	var identity = require_identity();
	var Pair = require_Pair();
	var Scalar = require_Scalar();
	var YAMLMap = require_YAMLMap();
	var YAMLSeq = require_YAMLSeq();
	var cst = require_cst();
	var lexer = require_lexer();
	var lineCounter = require_line_counter();
	var parser = require_parser();
	var publicApi = require_public_api();
	var visit = require_visit();
	exports.Composer = composer.Composer;
	exports.Document = Document.Document;
	exports.Schema = Schema.Schema;
	exports.YAMLError = errors.YAMLError;
	exports.YAMLParseError = errors.YAMLParseError;
	exports.YAMLWarning = errors.YAMLWarning;
	exports.Alias = Alias.Alias;
	exports.isAlias = identity.isAlias;
	exports.isCollection = identity.isCollection;
	exports.isDocument = identity.isDocument;
	exports.isMap = identity.isMap;
	exports.isNode = identity.isNode;
	exports.isPair = identity.isPair;
	exports.isScalar = identity.isScalar;
	exports.isSeq = identity.isSeq;
	exports.Pair = Pair.Pair;
	exports.Scalar = Scalar.Scalar;
	exports.YAMLMap = YAMLMap.YAMLMap;
	exports.YAMLSeq = YAMLSeq.YAMLSeq;
	exports.CST = cst;
	exports.Lexer = lexer.Lexer;
	exports.LineCounter = lineCounter.LineCounter;
	exports.Parser = parser.Parser;
	exports.parse = publicApi.parse;
	exports.parseAllDocuments = publicApi.parseAllDocuments;
	exports.parseDocument = publicApi.parseDocument;
	exports.stringify = publicApi.stringify;
	exports.visit = visit.visit;
	exports.visitAsync = visit.visitAsync;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/constants.js
var require_constants = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = {
		MAX_LENGTH: 256,
		MAX_SAFE_COMPONENT_LENGTH: 16,
		MAX_SAFE_BUILD_LENGTH: 250,
		MAX_SAFE_INTEGER: Number.MAX_SAFE_INTEGER || 
		/* istanbul ignore next */ 9007199254740991,
		WHITESPACE_CHARACTERS: [
			"	",
			"\n",
			"\v",
			"\f",
			"\r",
			" ",
			"\xA0",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			" ",
			"\u2028",
			"\u2029",
			" ",
			" ",
			"　",
			"﻿"
		],
		RELEASE_TYPES: [
			"major",
			"premajor",
			"minor",
			"preminor",
			"patch",
			"prepatch",
			"prerelease"
		],
		SEMVER_SPEC_VERSION: "2.0.0",
		FLAG_INCLUDE_PRERELEASE: 1,
		FLAG_LOOSE: 2
	};
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/debug.js
var require_debug = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = typeof process === "object" && process.env && process.env.NODE_DEBUG && /\bsemver\b/i.test(process.env.NODE_DEBUG) ? (...args) => console.error("SEMVER", ...args) : () => {};
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/re.js
var require_re = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { MAX_SAFE_COMPONENT_LENGTH, MAX_SAFE_BUILD_LENGTH, MAX_LENGTH } = require_constants();
	const debug = require_debug();
	exports = module.exports = {};
	const re = exports.re = [];
	const safeRe = exports.safeRe = [];
	const src = exports.src = [];
	const safeSrc = exports.safeSrc = [];
	const t = exports.t = {};
	let R = 0;
	const LETTERDASHNUMBER = "[a-zA-Z0-9-]";
	const safeRegexReplacements = [
		["\\s", 1],
		["\\d", MAX_LENGTH],
		[LETTERDASHNUMBER, MAX_SAFE_BUILD_LENGTH]
	];
	const makeSafeRegex = (value) => {
		for (const [token, max] of safeRegexReplacements) value = value.split(`${token}*`).join(`${token}{0,${max}}`).split(`${token}+`).join(`${token}{1,${max}}`);
		return value;
	};
	const createToken = (name, value, isGlobal) => {
		const safe = makeSafeRegex(value);
		const index = R++;
		debug(name, index, value);
		t[name] = index;
		src[index] = value;
		safeSrc[index] = safe;
		re[index] = new RegExp(value, isGlobal ? "g" : void 0);
		safeRe[index] = new RegExp(safe, isGlobal ? "g" : void 0);
	};
	createToken("NUMERICIDENTIFIER", "0|[1-9]\\d*");
	createToken("NUMERICIDENTIFIERLOOSE", "\\d+");
	createToken("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${LETTERDASHNUMBER}*`);
	createToken("MAINVERSION", `(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})`);
	createToken("MAINVERSIONLOOSE", `(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})`);
	createToken("PRERELEASEIDENTIFIER", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIER]})`);
	createToken("PRERELEASEIDENTIFIERLOOSE", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIERLOOSE]})`);
	createToken("PRERELEASE", `(?:-(${src[t.PRERELEASEIDENTIFIER]}(?:\\.${src[t.PRERELEASEIDENTIFIER]})*))`);
	createToken("PRERELEASELOOSE", `(?:-?(${src[t.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${src[t.PRERELEASEIDENTIFIERLOOSE]})*))`);
	createToken("BUILDIDENTIFIER", `${LETTERDASHNUMBER}+`);
	createToken("BUILD", `(?:\\+(${src[t.BUILDIDENTIFIER]}(?:\\.${src[t.BUILDIDENTIFIER]})*))`);
	createToken("FULLPLAIN", `v?${src[t.MAINVERSION]}${src[t.PRERELEASE]}?${src[t.BUILD]}?`);
	createToken("FULL", `^${src[t.FULLPLAIN]}$`);
	createToken("LOOSEPLAIN", `[v=\\s]*${src[t.MAINVERSIONLOOSE]}${src[t.PRERELEASELOOSE]}?${src[t.BUILD]}?`);
	createToken("LOOSE", `^${src[t.LOOSEPLAIN]}$`);
	createToken("GTLT", "((?:<|>)?=?)");
	createToken("XRANGEIDENTIFIERLOOSE", `${src[t.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);
	createToken("XRANGEIDENTIFIER", `${src[t.NUMERICIDENTIFIER]}|x|X|\\*`);
	createToken("XRANGEPLAIN", `[v=\\s]*(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:${src[t.PRERELEASE]})?${src[t.BUILD]}?)?)?`);
	createToken("XRANGEPLAINLOOSE", `[v=\\s]*(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:${src[t.PRERELEASELOOSE]})?${src[t.BUILD]}?)?)?`);
	createToken("XRANGE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAIN]}$`);
	createToken("XRANGELOOSE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAINLOOSE]}$`);
	createToken("COERCEPLAIN", `(^|[^\\d])(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}})(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?`);
	createToken("COERCE", `${src[t.COERCEPLAIN]}(?:$|[^\\d])`);
	createToken("COERCEFULL", src[t.COERCEPLAIN] + `(?:${src[t.PRERELEASE]})?(?:${src[t.BUILD]})?(?:$|[^\\d])`);
	createToken("COERCERTL", src[t.COERCE], true);
	createToken("COERCERTLFULL", src[t.COERCEFULL], true);
	createToken("LONETILDE", "(?:~>?)");
	createToken("TILDETRIM", `(\\s*)${src[t.LONETILDE]}\\s+`, true);
	exports.tildeTrimReplace = "$1~";
	createToken("TILDE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAIN]}$`);
	createToken("TILDELOOSE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAINLOOSE]}$`);
	createToken("LONECARET", "(?:\\^)");
	createToken("CARETTRIM", `(\\s*)${src[t.LONECARET]}\\s+`, true);
	exports.caretTrimReplace = "$1^";
	createToken("CARET", `^${src[t.LONECARET]}${src[t.XRANGEPLAIN]}$`);
	createToken("CARETLOOSE", `^${src[t.LONECARET]}${src[t.XRANGEPLAINLOOSE]}$`);
	createToken("COMPARATORLOOSE", `^${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]})$|^$`);
	createToken("COMPARATOR", `^${src[t.GTLT]}\\s*(${src[t.FULLPLAIN]})$|^$`);
	createToken("COMPARATORTRIM", `(\\s*)${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]}|${src[t.XRANGEPLAIN]})`, true);
	exports.comparatorTrimReplace = "$1$2$3";
	createToken("HYPHENRANGE", `^\\s*(${src[t.XRANGEPLAIN]})\\s+-\\s+(${src[t.XRANGEPLAIN]})\\s*$`);
	createToken("HYPHENRANGELOOSE", `^\\s*(${src[t.XRANGEPLAINLOOSE]})\\s+-\\s+(${src[t.XRANGEPLAINLOOSE]})\\s*$`);
	createToken("STAR", "(<|>)?=?\\s*\\*");
	createToken("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$");
	createToken("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$");
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/parse-options.js
var require_parse_options = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const looseOption = Object.freeze({ loose: true });
	const emptyOpts = Object.freeze({});
	const parseOptions = (options) => {
		if (!options) return emptyOpts;
		if (typeof options !== "object") return looseOption;
		return options;
	};
	module.exports = parseOptions;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/identifiers.js
var require_identifiers = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const numeric = /^[0-9]+$/;
	const compareIdentifiers = (a, b) => {
		if (typeof a === "number" && typeof b === "number") return a === b ? 0 : a < b ? -1 : 1;
		const anum = numeric.test(a);
		const bnum = numeric.test(b);
		if (anum && bnum) {
			a = +a;
			b = +b;
		}
		return a === b ? 0 : anum && !bnum ? -1 : bnum && !anum ? 1 : a < b ? -1 : 1;
	};
	const rcompareIdentifiers = (a, b) => compareIdentifiers(b, a);
	module.exports = {
		compareIdentifiers,
		rcompareIdentifiers
	};
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/classes/semver.js
var require_semver$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const debug = require_debug();
	const { MAX_LENGTH, MAX_SAFE_INTEGER } = require_constants();
	const { safeRe: re, t } = require_re();
	const parseOptions = require_parse_options();
	const { compareIdentifiers } = require_identifiers();
	const isPrereleaseIdentifier = (prerelease, identifier) => {
		const identifiers = identifier.split(".");
		if (identifiers.length > prerelease.length) return false;
		for (let i = 0; i < identifiers.length; i++) if (compareIdentifiers(prerelease[i], identifiers[i]) !== 0) return false;
		return true;
	};
	module.exports = class SemVer {
		constructor(version, options) {
			options = parseOptions(options);
			if (version instanceof SemVer) {
				if (version.loose === !!options.loose && version.includePrerelease === !!options.includePrerelease) return version;
				else version = version.version;
			} else if (typeof version !== "string") throw new TypeError(`Invalid version. Must be a string. Got type "${typeof version}".`);
			if (version.length > MAX_LENGTH) throw new TypeError(`version is longer than ${MAX_LENGTH} characters`);
			debug("SemVer", version, options);
			this.options = options;
			this.loose = !!options.loose;
			this.includePrerelease = !!options.includePrerelease;
			const m = version.trim().match(options.loose ? re[t.LOOSE] : re[t.FULL]);
			if (!m) throw new TypeError(`Invalid Version: ${version}`);
			this.raw = version;
			this.major = +m[1];
			this.minor = +m[2];
			this.patch = +m[3];
			if (this.major > MAX_SAFE_INTEGER || this.major < 0) throw new TypeError("Invalid major version");
			if (this.minor > MAX_SAFE_INTEGER || this.minor < 0) throw new TypeError("Invalid minor version");
			if (this.patch > MAX_SAFE_INTEGER || this.patch < 0) throw new TypeError("Invalid patch version");
			if (!m[4]) this.prerelease = [];
			else this.prerelease = m[4].split(".").map((id) => {
				if (/^[0-9]+$/.test(id)) {
					const num = +id;
					if (num >= 0 && num < MAX_SAFE_INTEGER) return num;
				}
				return id;
			});
			this.build = m[5] ? m[5].split(".") : [];
			this.format();
		}
		format() {
			this.version = `${this.major}.${this.minor}.${this.patch}`;
			if (this.prerelease.length) this.version += `-${this.prerelease.join(".")}`;
			return this.version;
		}
		toString() {
			return this.version;
		}
		compare(other) {
			debug("SemVer.compare", this.version, this.options, other);
			if (!(other instanceof SemVer)) {
				if (typeof other === "string" && other === this.version) return 0;
				other = new SemVer(other, this.options);
			}
			if (other.version === this.version) return 0;
			return this.compareMain(other) || this.comparePre(other);
		}
		compareMain(other) {
			if (!(other instanceof SemVer)) other = new SemVer(other, this.options);
			if (this.major < other.major) return -1;
			if (this.major > other.major) return 1;
			if (this.minor < other.minor) return -1;
			if (this.minor > other.minor) return 1;
			if (this.patch < other.patch) return -1;
			if (this.patch > other.patch) return 1;
			return 0;
		}
		comparePre(other) {
			if (!(other instanceof SemVer)) other = new SemVer(other, this.options);
			if (this.prerelease.length && !other.prerelease.length) return -1;
			else if (!this.prerelease.length && other.prerelease.length) return 1;
			else if (!this.prerelease.length && !other.prerelease.length) return 0;
			let i = 0;
			do {
				const a = this.prerelease[i];
				const b = other.prerelease[i];
				debug("prerelease compare", i, a, b);
				if (a === void 0 && b === void 0) return 0;
				else if (b === void 0) return 1;
				else if (a === void 0) return -1;
				else if (a === b) continue;
				else return compareIdentifiers(a, b);
			} while (++i);
		}
		compareBuild(other) {
			if (!(other instanceof SemVer)) other = new SemVer(other, this.options);
			let i = 0;
			do {
				const a = this.build[i];
				const b = other.build[i];
				debug("build compare", i, a, b);
				if (a === void 0 && b === void 0) return 0;
				else if (b === void 0) return 1;
				else if (a === void 0) return -1;
				else if (a === b) continue;
				else return compareIdentifiers(a, b);
			} while (++i);
		}
		inc(release, identifier, identifierBase) {
			if (release.startsWith("pre")) {
				if (!identifier && identifierBase === false) throw new Error("invalid increment argument: identifier is empty");
				if (identifier) {
					const match = `-${identifier}`.match(this.options.loose ? re[t.PRERELEASELOOSE] : re[t.PRERELEASE]);
					if (!match || match[1] !== identifier) throw new Error(`invalid identifier: ${identifier}`);
				}
			}
			switch (release) {
				case "premajor":
					this.prerelease.length = 0;
					this.patch = 0;
					this.minor = 0;
					this.major++;
					this.inc("pre", identifier, identifierBase);
					break;
				case "preminor":
					this.prerelease.length = 0;
					this.patch = 0;
					this.minor++;
					this.inc("pre", identifier, identifierBase);
					break;
				case "prepatch":
					this.prerelease.length = 0;
					this.inc("patch", identifier, identifierBase);
					this.inc("pre", identifier, identifierBase);
					break;
				case "prerelease":
					if (this.prerelease.length === 0) this.inc("patch", identifier, identifierBase);
					this.inc("pre", identifier, identifierBase);
					break;
				case "release":
					if (this.prerelease.length === 0) throw new Error(`version ${this.raw} is not a prerelease`);
					this.prerelease.length = 0;
					break;
				case "major":
					if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0) this.major++;
					this.minor = 0;
					this.patch = 0;
					this.prerelease = [];
					break;
				case "minor":
					if (this.patch !== 0 || this.prerelease.length === 0) this.minor++;
					this.patch = 0;
					this.prerelease = [];
					break;
				case "patch":
					if (this.prerelease.length === 0) this.patch++;
					this.prerelease = [];
					break;
				case "pre": {
					const base = Number(identifierBase) ? 1 : 0;
					if (this.prerelease.length === 0) this.prerelease = [base];
					else {
						let i = this.prerelease.length;
						while (--i >= 0) if (typeof this.prerelease[i] === "number") {
							this.prerelease[i]++;
							i = -2;
						}
						if (i === -1) {
							if (identifier === this.prerelease.join(".") && identifierBase === false) throw new Error("invalid increment argument: identifier already exists");
							this.prerelease.push(base);
						}
					}
					if (identifier) {
						let prerelease = [identifier, base];
						if (identifierBase === false) prerelease = [identifier];
						if (isPrereleaseIdentifier(this.prerelease, identifier)) {
							const prereleaseBase = this.prerelease[identifier.split(".").length];
							if (isNaN(prereleaseBase)) this.prerelease = prerelease;
						} else this.prerelease = prerelease;
					}
					break;
				}
				default: throw new Error(`invalid increment argument: ${release}`);
			}
			this.raw = this.format();
			if (this.build.length) this.raw += `+${this.build.join(".")}`;
			return this;
		}
	};
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/parse.js
var require_parse = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const parse = (version, options, throwErrors = false) => {
		if (version instanceof SemVer) return version;
		try {
			return new SemVer(version, options);
		} catch (er) {
			if (!throwErrors) return null;
			throw er;
		}
	};
	module.exports = parse;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/valid.js
var require_valid$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const parse = require_parse();
	const valid = (version, options) => {
		const v = parse(version, options);
		return v ? v.version : null;
	};
	module.exports = valid;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/clean.js
var require_clean = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const parse = require_parse();
	const clean = (version, options) => {
		const s = parse(version.trim().replace(/^[=v]+/, ""), options);
		return s ? s.version : null;
	};
	module.exports = clean;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/inc.js
var require_inc = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const inc = (version, release, options, identifier, identifierBase) => {
		if (typeof options === "string") {
			identifierBase = identifier;
			identifier = options;
			options = void 0;
		}
		try {
			return new SemVer(version instanceof SemVer ? version.version : version, options).inc(release, identifier, identifierBase).version;
		} catch (er) {
			return null;
		}
	};
	module.exports = inc;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/diff.js
var require_diff = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const parse = require_parse();
	const diff = (version1, version2) => {
		const v1 = parse(version1, null, true);
		const v2 = parse(version2, null, true);
		const comparison = v1.compare(v2);
		if (comparison === 0) return null;
		const v1Higher = comparison > 0;
		const highVersion = v1Higher ? v1 : v2;
		const lowVersion = v1Higher ? v2 : v1;
		const highHasPre = !!highVersion.prerelease.length;
		if (!!lowVersion.prerelease.length && !highHasPre) {
			if (!lowVersion.patch && !lowVersion.minor) return "major";
			if (lowVersion.compareMain(highVersion) === 0) {
				if (lowVersion.minor && !lowVersion.patch) return "minor";
				return "patch";
			}
		}
		const prefix = highHasPre ? "pre" : "";
		if (v1.major !== v2.major) return prefix + "major";
		if (v1.minor !== v2.minor) return prefix + "minor";
		if (v1.patch !== v2.patch) return prefix + "patch";
		return "prerelease";
	};
	module.exports = diff;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/major.js
var require_major = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const major = (a, loose) => new SemVer(a, loose).major;
	module.exports = major;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/minor.js
var require_minor = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const minor = (a, loose) => new SemVer(a, loose).minor;
	module.exports = minor;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/patch.js
var require_patch = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const patch = (a, loose) => new SemVer(a, loose).patch;
	module.exports = patch;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/prerelease.js
var require_prerelease = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const parse = require_parse();
	const prerelease = (version, options) => {
		const parsed = parse(version, options);
		return parsed && parsed.prerelease.length ? parsed.prerelease : null;
	};
	module.exports = prerelease;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/compare.js
var require_compare = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const compare = (a, b, loose) => new SemVer(a, loose).compare(new SemVer(b, loose));
	module.exports = compare;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/rcompare.js
var require_rcompare = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const rcompare = (a, b, loose) => compare(b, a, loose);
	module.exports = rcompare;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/compare-loose.js
var require_compare_loose = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const compareLoose = (a, b) => compare(a, b, true);
	module.exports = compareLoose;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/compare-build.js
var require_compare_build = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const compareBuild = (a, b, loose) => {
		const versionA = new SemVer(a, loose);
		const versionB = new SemVer(b, loose);
		return versionA.compare(versionB) || versionA.compareBuild(versionB);
	};
	module.exports = compareBuild;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/sort.js
var require_sort = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compareBuild = require_compare_build();
	const sort = (list, loose) => list.sort((a, b) => compareBuild(a, b, loose));
	module.exports = sort;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/rsort.js
var require_rsort = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compareBuild = require_compare_build();
	const rsort = (list, loose) => list.sort((a, b) => compareBuild(b, a, loose));
	module.exports = rsort;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/gt.js
var require_gt = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const gt = (a, b, loose) => compare(a, b, loose) > 0;
	module.exports = gt;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/lt.js
var require_lt = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const lt = (a, b, loose) => compare(a, b, loose) < 0;
	module.exports = lt;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/eq.js
var require_eq = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const eq = (a, b, loose) => compare(a, b, loose) === 0;
	module.exports = eq;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/neq.js
var require_neq = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const neq = (a, b, loose) => compare(a, b, loose) !== 0;
	module.exports = neq;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/gte.js
var require_gte = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const gte = (a, b, loose) => compare(a, b, loose) >= 0;
	module.exports = gte;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/lte.js
var require_lte = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const compare = require_compare();
	const lte = (a, b, loose) => compare(a, b, loose) <= 0;
	module.exports = lte;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/cmp.js
var require_cmp = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const eq = require_eq();
	const neq = require_neq();
	const gt = require_gt();
	const gte = require_gte();
	const lt = require_lt();
	const lte = require_lte();
	const cmp = (a, op, b, loose) => {
		switch (op) {
			case "===":
				if (typeof a === "object") a = a.version;
				if (typeof b === "object") b = b.version;
				return a === b;
			case "!==":
				if (typeof a === "object") a = a.version;
				if (typeof b === "object") b = b.version;
				return a !== b;
			case "":
			case "=":
			case "==": return eq(a, b, loose);
			case "!=": return neq(a, b, loose);
			case ">": return gt(a, b, loose);
			case ">=": return gte(a, b, loose);
			case "<": return lt(a, b, loose);
			case "<=": return lte(a, b, loose);
			default: throw new TypeError(`Invalid operator: ${op}`);
		}
	};
	module.exports = cmp;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/coerce.js
var require_coerce = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const parse = require_parse();
	const { safeRe: re, t } = require_re();
	const coerce = (version, options) => {
		if (version instanceof SemVer) return version;
		if (typeof version === "number") version = String(version);
		if (typeof version !== "string") return null;
		options = options || {};
		let match = null;
		if (!options.rtl) match = version.match(options.includePrerelease ? re[t.COERCEFULL] : re[t.COERCE]);
		else {
			const coerceRtlRegex = options.includePrerelease ? re[t.COERCERTLFULL] : re[t.COERCERTL];
			let next;
			while ((next = coerceRtlRegex.exec(version)) && (!match || match.index + match[0].length !== version.length)) {
				if (!match || next.index + next[0].length !== match.index + match[0].length) match = next;
				coerceRtlRegex.lastIndex = next.index + next[1].length + next[2].length;
			}
			coerceRtlRegex.lastIndex = -1;
		}
		if (match === null) return null;
		const major = match[2];
		const minor = match[3] || "0";
		const patch = match[4] || "0";
		const prerelease = options.includePrerelease && match[5] ? `-${match[5]}` : "";
		const build = options.includePrerelease && match[6] ? `+${match[6]}` : "";
		return parse(`${major}.${minor}.${patch}${prerelease}${build}`, options);
	};
	module.exports = coerce;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/truncate.js
var require_truncate = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const parse = require_parse();
	const constants = require_constants();
	const SemVer = require_semver$1();
	const truncate = (version, truncation, options) => {
		if (!constants.RELEASE_TYPES.includes(truncation)) return null;
		const clonedVersion = cloneInputVersion(version, options);
		return clonedVersion && doTruncation(clonedVersion, truncation);
	};
	const cloneInputVersion = (version, options) => {
		const versionStringToParse = version instanceof SemVer ? version.version : version;
		return parse(versionStringToParse, options);
	};
	const doTruncation = (version, truncation) => {
		if (isPrerelease(truncation)) return version.version;
		version.prerelease = [];
		switch (truncation) {
			case "major":
				version.minor = 0;
				version.patch = 0;
				break;
			case "minor": version.patch = 0;
		}
		return version.format();
	};
	const isPrerelease = (type) => {
		return type.startsWith("pre");
	};
	module.exports = truncate;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/lrucache.js
var require_lrucache = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var LRUCache = class {
		constructor() {
			this.max = 1e3;
			this.map = /* @__PURE__ */ new Map();
		}
		get(key) {
			const value = this.map.get(key);
			if (value === void 0) return;
			else {
				this.map.delete(key);
				this.map.set(key, value);
				return value;
			}
		}
		delete(key) {
			return this.map.delete(key);
		}
		set(key, value) {
			if (!this.delete(key) && value !== void 0) {
				if (this.map.size >= this.max) {
					const firstKey = this.map.keys().next().value;
					this.delete(firstKey);
				}
				this.map.set(key, value);
			}
			return this;
		}
	};
	module.exports = LRUCache;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/internal/trim-comparator-whitespace.js
var require_trim_comparator_whitespace = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { MAX_LENGTH, MAX_SAFE_BUILD_LENGTH, WHITESPACE_CHARACTERS } = require_constants();
	/**
	* Remembers the last two rows of digits so their characters need not be reread.
	* Positions start at -1 until a row has been found.
	*
	* @typedef {object} DigitRunCache
	* @property {number} start The first character of the most recently found row.
	* @property {number} end The position after that row's last character.
	* @property {number} previousStart The first character of the previous row.
	* @property {number} previousEnd The position after the previous row.
	*/
	const whitespace = /* @__PURE__ */ new Uint8Array(65536);
	for (const char of WHITESPACE_CHARACTERS) whitespace[char.charCodeAt(0)] = 1;
	/**
	* Checks whether a character is whitespace, like a space, tab, or newline.
	* Looking past the end of the string returns false.
	*
	* @param {string|undefined} char One character, or undefined past the string's end.
	* @returns {boolean} Whether the character is whitespace.
	* @example isWhitespace(' ') // true
	* @example isWhitespace('1') // false
	*/
	const isWhitespace = (char) => char !== void 0 && whitespace[char.charCodeAt(0)] === 1;
	/**
	* Checks for v, =, or whitespace before the version number.
	* These are historical version prefixes, not range operators:
	* < and > are handled separately, as are tilde and caret ranges.
	*
	* @param {string|undefined} char One character to check.
	* @returns {boolean} Whether the character can belong to a version prefix.
	* @example isVersionPrefix('=') // true
	* @example isVersionPrefix('>') // false
	*/
	const isVersionPrefix = (char) => char === "v" || char === "=" || isWhitespace(char);
	/**
	* Checks whether a character is one of the digits 0 through 9.
	*
	* @param {string|undefined} char One character to check.
	* @returns {boolean} Whether the character is an ASCII digit.
	* @example isDigit('7') // true
	* @example isDigit('.') // false
	*/
	const isDigit = (char) => char !== void 0 && char >= "0" && char <= "9";
	/**
	* Checks whether a character is an English letter, uppercase or lowercase.
	*
	* @param {string|undefined} char One character to check.
	* @returns {boolean} Whether the character is an ASCII letter.
	* @example isLetter('b') // true
	* @example isLetter('7') // false
	*/
	const isLetter = (char) => char !== void 0 && (char >= "a" && char <= "z" || char >= "A" && char <= "Z");
	/**
	* Checks for a letter, digit, or hyphen: the characters allowed inside
	* prerelease and build names such as beta-1.
	*
	* @param {string|undefined} char One character to check.
	* @returns {boolean} Whether the character can be part of an identifier.
	* @example isIdentifierCharacter('-') // true
	* @example isIdentifierCharacter('.') // false; dots separate identifiers
	*/
	const isIdentifierCharacter = (char) => isDigit(char) || isLetter(char) || char === "-";
	/**
	* Checks whether a version component can begin here: with a digit or
	* a wildcard such as x, X, or *.
	*
	* @param {string|undefined} char One character to check.
	* @returns {boolean} Whether a number or wildcard can start with this character.
	* @example isVersionStart('x') // true
	* @example isVersionStart('v') // false; v belongs to the prefix
	*/
	const isVersionStart = (char) => isDigit(char) || char === "x" || char === "X" || char === "*";
	/**
	* Finds the end of a row of digits, but returns no more than limit digits.
	* Remembers the last two rows so looking at them again does not reread them.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position of the first character to check.
	* @param {number} limit The most digit characters the returned match can include.
	* @param {DigitRunCache} digitRuns Shared cache of digit-run positions, updated in place.
	* @returns {number} The position after the matched digits, or start if none match.
	* @example findDigitsEndIndex('123abc', 0, 10, digitRuns) // 3, pointing at a
	* @example findDigitsEndIndex('123abc', 0, 2, digitRuns) // 2, pointing at the unread 3
	*/
	const findDigitsEndIndex = (range, start, limit, digitRuns) => {
		if (!isDigit(range[start])) return start;
		if (start >= digitRuns.start && start < digitRuns.end) return Math.min(start + limit, digitRuns.end);
		if (start >= digitRuns.previousStart && start < digitRuns.previousEnd) return Math.min(start + limit, digitRuns.previousEnd);
		let end = start + 1;
		while (isDigit(range[end])) end++;
		digitRuns.previousStart = digitRuns.start;
		digitRuns.previousEnd = digitRuns.end;
		digitRuns.start = start;
		digitRuns.end = end;
		return Math.min(start + limit, end);
	};
	/**
	* Reads a number using the old regex's length and leading-zero rules.
	* Strict mode reads just the first zero in 012; loose mode can read all three.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position where the number should begin.
	* @param {boolean} loose Whether to allow leading zeros.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position after the matched digits, not their numeric value.
	* @example findVersionNumberEndIndex('012', 0, false, digitRuns) // 1
	* @example findVersionNumberEndIndex('012', 0, true, digitRuns) // 3
	*/
	const findVersionNumberEndIndex = (range, start, loose, digitRuns) => {
		if (!loose && range[start] === "0") return start + 1;
		return findDigitsEndIndex(range, start, loose ? MAX_LENGTH : MAX_LENGTH + 1, digitRuns);
	};
	/**
	* Reads one piece of a prerelease name, such as beta or 1 in beta.1.
	* Tries the letter-or-hyphen form first, then the number-only form.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position where the identifier should begin.
	* @param {boolean} loose Whether numeric identifiers may have leading zeros.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position after the identifier, or start if none matches.
	* @example findPrereleaseIdentifierEndIndex('beta.1', 0, false, digitRuns) // 4, at the dot
	* @example findPrereleaseIdentifierEndIndex('001beta', 0, false, digitRuns) // 7
	*/
	const findPrereleaseIdentifierEndIndex = (range, start, loose, digitRuns) => {
		const digitsEnd = findDigitsEndIndex(range, start, MAX_LENGTH, digitRuns);
		if (isLetter(range[digitsEnd]) || range[digitsEnd] === "-") {
			let end = digitsEnd + 1;
			const limit = end + MAX_SAFE_BUILD_LENGTH;
			while (end < limit && isIdentifierCharacter(range[end])) end++;
			return end;
		}
		return findVersionNumberEndIndex(range, start, loose, digitRuns);
	};
	/**
	* Reads a prerelease suffix such as -beta.1, one dot-separated piece at a time.
	* Loose mode also allows the name without its opening hyphen.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position where the suffix should begin, including -.
	* @param {boolean} loose Whether the opening hyphen is optional and zeros allowed.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position after the matched suffix, or start if absent.
	* @example findPrereleaseEndIndex('-beta.1+sha', 0, false, digitRuns) // 7, at the plus
	* @example findPrereleaseEndIndex('beta', 0, false, digitRuns) // 0; no opening hyphen
	*/
	const findPrereleaseEndIndex = (range, start, loose, digitRuns) => {
		const hyphen = range[start] === "-";
		if (!loose && !hyphen) return start;
		const identifierStart = start + (hyphen ? 1 : 0);
		let end = findPrereleaseIdentifierEndIndex(range, identifierStart, loose, digitRuns);
		if (end === identifierStart) {
			if (!loose || !hyphen) return start;
			end = findPrereleaseIdentifierEndIndex(range, start, loose, digitRuns);
		}
		while (range[end] === ".") {
			const next = findPrereleaseIdentifierEndIndex(range, end + 1, loose, digitRuns);
			if (next === end + 1) break;
			end = next;
		}
		return end;
	};
	/**
	* Reads one build-name piece, such as sha or 123 in +sha.123.
	* Stops at a disallowed character or the old regex's length limit.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position where the identifier should begin.
	* @returns {number} The position after the identifier, or start if none matches.
	* @example findBuildIdentifierEndIndex('sha.123', 0) // 3, at the dot
	* @example findBuildIdentifierEndIndex('001', 0) // 3; leading zeros are allowed
	*/
	const findBuildIdentifierEndIndex = (range, start) => {
		let end = start;
		while (end - start < MAX_SAFE_BUILD_LENGTH && isIdentifierCharacter(range[end])) end++;
		return end;
	};
	/**
	* Reads optional build metadata such as +sha.123.
	* Leaves the position unchanged if there is no plus sign followed by a name.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position where the opening + should be.
	* @returns {number} The position after the matched metadata, or start if absent.
	* @example findBuildEndIndex('+sha.123 <2', 0) // 8, at the space
	* @example findBuildEndIndex('+', 0) // 0; a plus sign alone is not a match
	*/
	const findBuildEndIndex = (range, start) => {
		if (range[start] !== "+") return start;
		let end = findBuildIdentifierEndIndex(range, start + 1);
		if (end === start + 1) return start;
		while (range[end] === ".") {
			const next = findBuildIdentifierEndIndex(range, end + 1);
			if (next === end + 1) break;
			end = next;
		}
		return end;
	};
	/**
	* Reads three numbers separated by dots, then any prerelease and build suffixes.
	* Uses loose rules, so forms such as 01.02.03beta can match here.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position of the first number, after any prefix.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position after the version match, or start if none matches.
	* @example findLooseFullVersionEndIndex('1.2.3-beta+sha <2', 0, digitRuns) // 14
	* @example findLooseFullVersionEndIndex('1.2', 0, digitRuns) // 0; needs three numbers
	*/
	const findLooseFullVersionEndIndex = (range, start, digitRuns) => {
		let end = start;
		for (let component = 0; component < 3; component++) {
			const next = findVersionNumberEndIndex(range, end, true, digitRuns);
			if (next === end) return start;
			end = next;
			if (component < 2) {
				if (range[end] !== ".") return start;
				end++;
			}
		}
		const prereleaseEnd = findPrereleaseEndIndex(range, end, true, digitRuns);
		return findBuildEndIndex(range, prereleaseEnd);
	};
	/**
	* Reads one component of a partial or wildcard version, such as 2 or x in 2.x.
	* Numbers use strict leading-zero rules; wildcards take up one character.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position where the component should begin.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position after the component, or start if none matches.
	* @example findPartialVersionComponentEndIndex('2.x', 0, digitRuns) // 1, at the dot
	* @example findPartialVersionComponentEndIndex('2.x', 2, digitRuns) // 3, after x
	*/
	const findPartialVersionComponentEndIndex = (range, start, digitRuns) => {
		if (isDigit(range[start])) return findVersionNumberEndIndex(range, start, false, digitRuns);
		return isVersionStart(range[start]) ? start + 1 : start;
	};
	/**
	* Reads up to three components, allowing forms such as 1, 1.2, or 1.x.
	* After the third component, also reads any strict prerelease and build suffixes.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position of a number or wildcard, after any prefix.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position after the matched version text.
	* @example findPartialVersionEndIndex('1.x <2', 0, digitRuns) // 3, at the space
	* @example findPartialVersionEndIndex('1.', 0, digitRuns) // 1; the trailing dot is unread
	*/
	const findPartialVersionEndIndex = (range, start, digitRuns) => {
		let end = findPartialVersionComponentEndIndex(range, start, digitRuns);
		for (let component = 0; component < 2; component++) {
			if (range[end] !== ".") return end;
			const next = findPartialVersionComponentEndIndex(range, end + 1, digitRuns);
			if (next === end + 1) return end;
			end = next;
		}
		const prereleaseEnd = findPrereleaseEndIndex(range, end, false, digitRuns);
		return findBuildEndIndex(range, prereleaseEnd);
	};
	/**
	* Finds where a version match ends, without deciding whether the range is valid.
	* Tries a loose full version first, then a partial or wildcard version, just
	* like the old regex's LOOSEPLAIN and XRANGEPLAIN alternatives.
	*
	* @param {string} range The text to read; it is not changed.
	* @param {number} start The position of a number or wildcard, after any prefix.
	* @param {DigitRunCache} digitRuns Shared digit-run cache, updated as needed.
	* @returns {number} The position where scanning the next candidate can resume.
	* @example findVersionEndIndex('1.2.3 <2', 0, digitRuns) // 5, at the space
	* @example findVersionEndIndex('1.x <2', 0, digitRuns) // 3, at the space
	*/
	const findVersionEndIndex = (range, start, digitRuns) => {
		const fullVersionEnd = findLooseFullVersionEndIndex(range, start, digitRuns);
		return fullVersionEnd !== start ? fullVersionEnd : findPartialVersionEndIndex(range, start, digitRuns);
	};
	/**
	* Finds the one whitespace character the old replacement would remove.
	* Keeps leading whitespace, skips an optional operator, and checks immediately
	* after it. Returns -1 if there is nothing to remove.
	*
	* @param {string} range The text containing a candidate already found by the caller.
	* @param {number} matchStart The candidate's position, including leading whitespace.
	* @returns {number} The position of the removable whitespace, or -1 if absent.
	* @example findRemovableWhitespaceIndex(' > 1', 0) // 2; keep the space at position 0
	* @example findRemovableWhitespaceIndex('>1', 0) // -1
	*/
	const findRemovableWhitespaceIndex = (range, matchStart) => {
		let position = matchStart;
		if (isWhitespace(range[position])) position++;
		if (range[position] === "<" || range[position] === ">") position++;
		if (range[position] === "=") position++;
		return isWhitespace(range[position]) ? position : -1;
	};
	/**
	* Joins an operator to its version, turning > 1.2.3 into >1.2.3.
	* Copies everything else according to the old regex's matching rules.
	* Moves forward through prefixes and whole versions to avoid repeatedly
	* searching the same characters on long inputs.
	*
	* @param {string} range The range text to process; the original string is unchanged.
	* @returns {string} The range with matched operator whitespace removed.
	* @example trimComparatorWhitespace('> 1.2.3 < 2') // '>1.2.3 <2'
	* @example trimComparatorWhitespace('> invalid') // '> invalid'
	*/
	const trimComparatorWhitespace = (range) => {
		let result = "";
		let copyFrom = 0;
		let cursor = 0;
		const digitRuns = {
			start: -1,
			end: -1,
			previousStart: -1,
			previousEnd: -1
		};
		while (cursor < range.length) {
			const matchStart = cursor;
			if (range[cursor] === "<" || range[cursor] === ">") cursor++;
			else if (!isVersionPrefix(range[cursor]) && !isVersionStart(range[cursor])) {
				cursor++;
				continue;
			}
			while (cursor < range.length && isVersionPrefix(range[cursor])) cursor++;
			if (!isVersionStart(range[cursor])) continue;
			const whitespacePosition = findRemovableWhitespaceIndex(range, matchStart);
			if (whitespacePosition !== -1) {
				result += range.slice(copyFrom, whitespacePosition);
				copyFrom = whitespacePosition + 1;
			}
			cursor = findVersionEndIndex(range, cursor, digitRuns);
		}
		return result + range.slice(copyFrom);
	};
	module.exports = trimComparatorWhitespace;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/classes/range.js
var require_range = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SPACE_CHARACTERS = /\s+/g;
	module.exports = class Range {
		constructor(range, options) {
			options = parseOptions(options);
			if (range instanceof Range) {
				if (range.loose === !!options.loose && range.includePrerelease === !!options.includePrerelease) return range;
				else return new Range(range.raw, options);
			}
			if (range instanceof Comparator) {
				this.raw = range.value;
				this.set = [[range]];
				this.formatted = void 0;
				return this;
			}
			this.options = options;
			this.loose = !!options.loose;
			this.includePrerelease = !!options.includePrerelease;
			this.raw = range.trim().replace(SPACE_CHARACTERS, " ");
			this.set = this.raw.split("||").map((r) => this.parseRange(r.trim())).filter((c) => c.length);
			if (!this.set.length) throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
			if (this.set.length > 1) {
				const first = this.set[0];
				this.set = this.set.filter((c) => !isNullSet(c[0]));
				if (this.set.length === 0) this.set = [first];
				else if (this.set.length > 1) {
					for (const c of this.set) if (c.length === 1 && isAny(c[0])) {
						this.set = [c];
						break;
					}
				}
			}
			this.formatted = void 0;
		}
		get range() {
			if (this.formatted === void 0) {
				this.formatted = "";
				for (let i = 0; i < this.set.length; i++) {
					if (i > 0) this.formatted += "||";
					const comps = this.set[i];
					for (let k = 0; k < comps.length; k++) {
						if (k > 0) this.formatted += " ";
						this.formatted += comps[k].toString().trim();
					}
				}
			}
			return this.formatted;
		}
		format() {
			return this.range;
		}
		toString() {
			return this.range;
		}
		parseRange(range) {
			range = range.replace(BUILDSTRIPRE, "");
			const memoKey = ((this.options.includePrerelease && FLAG_INCLUDE_PRERELEASE) | (this.options.loose && FLAG_LOOSE)) + ":" + range;
			const cached = cache.get(memoKey);
			if (cached) return cached;
			const loose = this.options.loose;
			const hr = loose ? re[t.HYPHENRANGELOOSE] : re[t.HYPHENRANGE];
			range = range.replace(hr, hyphenReplace(this.options.includePrerelease));
			debug("hyphen replace", range);
			range = trimComparatorWhitespace(range);
			debug("comparator trim", range);
			range = range.replace(re[t.TILDETRIM], tildeTrimReplace);
			debug("tilde trim", range);
			range = range.replace(re[t.CARETTRIM], caretTrimReplace);
			debug("caret trim", range);
			let rangeList = range.split(" ").map((comp) => parseComparator(comp, this.options)).join(" ").split(/\s+/).map((comp) => replaceGTE0(comp, this.options));
			if (loose) rangeList = rangeList.filter((comp) => {
				debug("loose invalid filter", comp, this.options);
				return !!comp.match(re[t.COMPARATORLOOSE]);
			});
			debug("range list", rangeList);
			const rangeMap = /* @__PURE__ */ new Map();
			const comparators = rangeList.map((comp) => new Comparator(comp, this.options));
			for (const comp of comparators) {
				if (isNullSet(comp)) return [comp];
				rangeMap.set(comp.value, comp);
			}
			if (rangeMap.size > 1 && rangeMap.has("")) rangeMap.delete("");
			const result = [...rangeMap.values()];
			cache.set(memoKey, result);
			return result;
		}
		intersects(range, options) {
			if (!(range instanceof Range)) throw new TypeError("a Range is required");
			return this.set.some((thisComparators) => {
				return isSatisfiable(thisComparators, options) && range.set.some((rangeComparators) => {
					return isSatisfiable(rangeComparators, options) && thisComparators.every((thisComparator) => {
						return rangeComparators.every((rangeComparator) => {
							return thisComparator.intersects(rangeComparator, options);
						});
					});
				});
			});
		}
		test(version) {
			if (!version) return false;
			if (typeof version === "string") try {
				version = new SemVer(version, this.options);
			} catch (er) {
				return false;
			}
			for (let i = 0; i < this.set.length; i++) if (testSet(this.set[i], version, this.options)) return true;
			return false;
		}
	};
	const cache = new (require_lrucache())();
	const parseOptions = require_parse_options();
	const Comparator = require_comparator();
	const debug = require_debug();
	const SemVer = require_semver$1();
	const trimComparatorWhitespace = require_trim_comparator_whitespace();
	const { safeRe: re, src, t, tildeTrimReplace, caretTrimReplace } = require_re();
	const { FLAG_INCLUDE_PRERELEASE, FLAG_LOOSE } = require_constants();
	const BUILDSTRIPRE = new RegExp(src[t.BUILD], "g");
	const isNullSet = (c) => c.value === "<0.0.0-0";
	const isAny = (c) => c.value === "";
	const isSatisfiable = (comparators, options) => {
		let result = true;
		const remainingComparators = comparators.slice();
		let testComparator = remainingComparators.pop();
		while (result && remainingComparators.length) {
			result = remainingComparators.every((otherComparator) => {
				return testComparator.intersects(otherComparator, options);
			});
			testComparator = remainingComparators.pop();
		}
		return result;
	};
	const parseComparator = (comp, options) => {
		comp = comp.replace(re[t.BUILD], "");
		debug("comp", comp, options);
		comp = replaceCarets(comp, options);
		debug("caret", comp);
		comp = replaceTildes(comp, options);
		debug("tildes", comp);
		comp = replaceXRanges(comp, options);
		debug("xrange", comp);
		comp = replaceStars(comp, options);
		debug("stars", comp);
		return comp;
	};
	const isX = (id) => !id || id.toLowerCase() === "x" || id === "*";
	const invalidXRangeOrder = (M, m, p) => isX(M) && !isX(m) || isX(m) && p && !isX(p);
	const replaceTildes = (comp, options) => {
		return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options)).join(" ");
	};
	const replaceTilde = (comp, options) => {
		const r = options.loose ? re[t.TILDELOOSE] : re[t.TILDE];
		const z = options.includePrerelease ? "-0" : "";
		return comp.replace(r, (_, M, m, p, pr) => {
			debug("tilde", comp, _, M, m, p, pr);
			let ret;
			if (isX(M)) ret = "";
			else if (isX(m)) ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
			else if (isX(p)) ret = `>=${M}.${m}.0${z} <${M}.${+m + 1}.0-0`;
			else if (pr) {
				debug("replaceTilde pr", pr);
				ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
			} else ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
			debug("tilde return", ret);
			return ret;
		});
	};
	const replaceCarets = (comp, options) => {
		return comp.trim().split(/\s+/).map((c) => replaceCaret(c, options)).join(" ");
	};
	const replaceCaret = (comp, options) => {
		debug("caret", comp, options);
		const r = options.loose ? re[t.CARETLOOSE] : re[t.CARET];
		const z = options.includePrerelease ? "-0" : "";
		return comp.replace(r, (_, M, m, p, pr) => {
			debug("caret", comp, _, M, m, p, pr);
			let ret;
			if (isX(M)) ret = "";
			else if (isX(m)) ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
			else if (isX(p)) {
				if (M === "0") ret = `>=${M}.${m}.0${z} <${M}.${+m + 1}.0-0`;
				else ret = `>=${M}.${m}.0${z} <${+M + 1}.0.0-0`;
			} else if (pr) {
				debug("replaceCaret pr", pr);
				if (M === "0") {
					if (m === "0") ret = `>=${M}.${m}.${p}-${pr} <${M}.${m}.${+p + 1}-0`;
					else ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
				} else ret = `>=${M}.${m}.${p}-${pr} <${+M + 1}.0.0-0`;
			} else {
				debug("no pr");
				if (M === "0") {
					if (m === "0") ret = `>=${M}.${m}.${p} <${M}.${m}.${+p + 1}-0`;
					else ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
				} else ret = `>=${M}.${m}.${p} <${+M + 1}.0.0-0`;
			}
			debug("caret return", ret);
			return ret;
		});
	};
	const replaceXRanges = (comp, options) => {
		debug("replaceXRanges", comp, options);
		return comp.split(/\s+/).map((c) => replaceXRange(c, options)).join(" ");
	};
	const replaceXRange = (comp, options) => {
		comp = comp.trim();
		const r = options.loose ? re[t.XRANGELOOSE] : re[t.XRANGE];
		return comp.replace(r, (ret, gtlt, M, m, p, pr) => {
			debug("xRange", comp, ret, gtlt, M, m, p, pr);
			if (invalidXRangeOrder(M, m, p)) return comp;
			const xM = isX(M);
			const xm = xM || isX(m);
			const xp = xm || isX(p);
			const anyX = xp;
			if (gtlt === "=" && anyX) gtlt = "";
			pr = options.includePrerelease ? "-0" : "";
			if (xM) {
				if (gtlt === ">" || gtlt === "<") ret = "<0.0.0-0";
				else ret = "*";
			} else if (gtlt && anyX) {
				if (xm) m = 0;
				p = 0;
				if (gtlt === ">") {
					gtlt = ">=";
					if (xm) {
						M = +M + 1;
						m = 0;
						p = 0;
					} else {
						m = +m + 1;
						p = 0;
					}
				} else if (gtlt === "<=") {
					gtlt = "<";
					if (xm) M = +M + 1;
					else m = +m + 1;
				}
				if (gtlt === "<") pr = "-0";
				ret = `${gtlt + M}.${m}.${p}${pr}`;
			} else if (xm) ret = `>=${M}.0.0${pr} <${+M + 1}.0.0-0`;
			else if (xp) ret = `>=${M}.${m}.0${pr} <${M}.${+m + 1}.0-0`;
			debug("xRange return", ret);
			return ret;
		});
	};
	const replaceStars = (comp, options) => {
		debug("replaceStars", comp, options);
		return comp.trim().replace(re[t.STAR], "");
	};
	const replaceGTE0 = (comp, options) => {
		debug("replaceGTE0", comp, options);
		return comp.trim().replace(re[options.includePrerelease ? t.GTE0PRE : t.GTE0], "");
	};
	const hyphenReplace = (incPr) => ($0, from, fM, fm, fp, fpr, fb, to, tM, tm, tp, tpr) => {
		if (isX(fM)) from = "";
		else if (isX(fm)) from = `>=${fM}.0.0${incPr ? "-0" : ""}`;
		else if (isX(fp)) from = `>=${fM}.${fm}.0${incPr ? "-0" : ""}`;
		else if (fpr) from = `>=${from}`;
		else from = `>=${from}${incPr ? "-0" : ""}`;
		if (isX(tM)) to = "";
		else if (isX(tm)) to = `<${+tM + 1}.0.0-0`;
		else if (isX(tp)) to = `<${tM}.${+tm + 1}.0-0`;
		else if (tpr) to = `<=${tM}.${tm}.${tp}-${tpr}`;
		else if (incPr) to = `<${tM}.${tm}.${+tp + 1}-0`;
		else to = `<=${to}`;
		return `${from} ${to}`.trim();
	};
	const testSet = (set, version, options) => {
		for (let i = 0; i < set.length; i++) if (!set[i].test(version)) return false;
		if (version.prerelease.length && !options.includePrerelease) {
			for (let i = 0; i < set.length; i++) {
				debug(set[i].semver);
				if (set[i].semver === Comparator.ANY) continue;
				if (set[i].semver.prerelease.length > 0) {
					const allowed = set[i].semver;
					if (allowed.major === version.major && allowed.minor === version.minor && allowed.patch === version.patch) return true;
				}
			}
			return false;
		}
		return true;
	};
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/classes/comparator.js
var require_comparator = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const ANY = Symbol("SemVer ANY");
	module.exports = class Comparator {
		static get ANY() {
			return ANY;
		}
		constructor(comp, options) {
			options = parseOptions(options);
			if (comp instanceof Comparator) {
				if (comp.loose === !!options.loose) return comp;
				else comp = comp.value;
			}
			comp = comp.trim().split(/\s+/).join(" ");
			debug("comparator", comp, options);
			this.options = options;
			this.loose = !!options.loose;
			this.parse(comp);
			if (this.semver === ANY) this.value = "";
			else this.value = this.operator + this.semver.version;
			debug("comp", this);
		}
		parse(comp) {
			const r = this.options.loose ? re[t.COMPARATORLOOSE] : re[t.COMPARATOR];
			const m = comp.match(r);
			if (!m) throw new TypeError(`Invalid comparator: ${comp}`);
			this.operator = m[1] !== void 0 ? m[1] : "";
			if (this.operator === "=") this.operator = "";
			if (!m[2]) this.semver = ANY;
			else this.semver = new SemVer(m[2], this.options.loose);
		}
		toString() {
			return this.value;
		}
		test(version) {
			debug("Comparator.test", version, this.options.loose);
			if (this.semver === ANY || version === ANY) return true;
			if (typeof version === "string") try {
				version = new SemVer(version, this.options);
			} catch (er) {
				return false;
			}
			return cmp(version, this.operator, this.semver, this.options);
		}
		intersects(comp, options) {
			if (!(comp instanceof Comparator)) throw new TypeError("a Comparator is required");
			if (this.operator === "") {
				if (this.value === "") return true;
				return new Range(comp.value, options).test(this.value);
			} else if (comp.operator === "") {
				if (comp.value === "") return true;
				return new Range(this.value, options).test(comp.semver);
			}
			options = parseOptions(options);
			if (options.includePrerelease && (this.value === "<0.0.0-0" || comp.value === "<0.0.0-0")) return false;
			if (!options.includePrerelease && (this.value.startsWith("<0.0.0") || comp.value.startsWith("<0.0.0"))) return false;
			if (this.operator.startsWith(">") && comp.operator.startsWith(">")) return true;
			if (this.operator.startsWith("<") && comp.operator.startsWith("<")) return true;
			if (this.semver.version === comp.semver.version && this.operator.includes("=") && comp.operator.includes("=")) return true;
			if (cmp(this.semver, "<", comp.semver, options) && this.operator.startsWith(">") && comp.operator.startsWith("<")) return true;
			if (cmp(this.semver, ">", comp.semver, options) && this.operator.startsWith("<") && comp.operator.startsWith(">")) return true;
			return false;
		}
	};
	const parseOptions = require_parse_options();
	const { safeRe: re, t } = require_re();
	const cmp = require_cmp();
	const debug = require_debug();
	const SemVer = require_semver$1();
	const Range = require_range();
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/functions/satisfies.js
var require_satisfies = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const Range = require_range();
	const satisfies = (version, range, options) => {
		try {
			range = new Range(range, options);
		} catch (er) {
			return false;
		}
		return range.test(version);
	};
	module.exports = satisfies;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/to-comparators.js
var require_to_comparators = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const Range = require_range();
	const toComparators = (range, options) => new Range(range, options).set.map((comp) => comp.map((c) => c.value).join(" ").trim().split(" "));
	module.exports = toComparators;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/max-satisfying.js
var require_max_satisfying = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const Range = require_range();
	const maxSatisfying = (versions, range, options) => {
		let max = null;
		let maxSV = null;
		let rangeObj = null;
		try {
			rangeObj = new Range(range, options);
		} catch (er) {
			return null;
		}
		versions.forEach((v) => {
			if (rangeObj.test(v)) {
				if (!max || maxSV.compare(v) === -1) {
					max = v;
					maxSV = new SemVer(max, options);
				}
			}
		});
		return max;
	};
	module.exports = maxSatisfying;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/min-satisfying.js
var require_min_satisfying = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const Range = require_range();
	const minSatisfying = (versions, range, options) => {
		let min = null;
		let minSV = null;
		let rangeObj = null;
		try {
			rangeObj = new Range(range, options);
		} catch (er) {
			return null;
		}
		versions.forEach((v) => {
			if (rangeObj.test(v)) {
				if (!min || minSV.compare(v) === 1) {
					min = v;
					minSV = new SemVer(min, options);
				}
			}
		});
		return min;
	};
	module.exports = minSatisfying;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/min-version.js
var require_min_version = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const Range = require_range();
	const gt = require_gt();
	const minVersion = (range, loose) => {
		range = new Range(range, loose);
		let minver = new SemVer("0.0.0");
		if (range.test(minver)) return minver;
		minver = new SemVer("0.0.0-0");
		if (range.test(minver)) return minver;
		minver = null;
		for (let i = 0; i < range.set.length; ++i) {
			const comparators = range.set[i];
			let setMin = null;
			comparators.forEach((comparator) => {
				const compver = new SemVer(comparator.semver.version);
				switch (comparator.operator) {
					case ">":
						if (compver.prerelease.length === 0) compver.patch++;
						else compver.prerelease.push(0);
						compver.raw = compver.format();
					case "":
					case ">=":
						if (!setMin || gt(compver, setMin)) setMin = compver;
						break;
					case "<":
					case "<=": break;
					/* istanbul ignore next */
					default: throw new Error(`Unexpected operation: ${comparator.operator}`);
				}
			});
			if (setMin && (!minver || gt(minver, setMin))) minver = setMin;
		}
		if (minver && range.test(minver)) return minver;
		return null;
	};
	module.exports = minVersion;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/valid.js
var require_valid = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const Range = require_range();
	const validRange = (range, options) => {
		try {
			return new Range(range, options).range || "*";
		} catch (er) {
			return null;
		}
	};
	module.exports = validRange;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/outside.js
var require_outside = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const SemVer = require_semver$1();
	const Comparator = require_comparator();
	const { ANY } = Comparator;
	const Range = require_range();
	const satisfies = require_satisfies();
	const gt = require_gt();
	const lt = require_lt();
	const lte = require_lte();
	const gte = require_gte();
	const outside = (version, range, hilo, options) => {
		version = new SemVer(version, options);
		range = new Range(range, options);
		let gtfn, ltefn, ltfn, comp, ecomp;
		switch (hilo) {
			case ">":
				gtfn = gt;
				ltefn = lte;
				ltfn = lt;
				comp = ">";
				ecomp = ">=";
				break;
			case "<":
				gtfn = lt;
				ltefn = gte;
				ltfn = gt;
				comp = "<";
				ecomp = "<=";
				break;
			default: throw new TypeError("Must provide a hilo val of \"<\" or \">\"");
		}
		if (satisfies(version, range, options)) return false;
		for (let i = 0; i < range.set.length; ++i) {
			const comparators = range.set[i];
			let high = null;
			let low = null;
			comparators.forEach((comparator) => {
				if (comparator.semver === ANY) comparator = new Comparator(">=0.0.0");
				high = high || comparator;
				low = low || comparator;
				if (gtfn(comparator.semver, high.semver, options)) high = comparator;
				else if (ltfn(comparator.semver, low.semver, options)) low = comparator;
			});
			if (high.operator === comp || high.operator === ecomp) return false;
			if ((!low.operator || low.operator === comp) && ltefn(version, low.semver)) return false;
			else if (low.operator === ecomp && ltfn(version, low.semver)) return false;
		}
		return true;
	};
	module.exports = outside;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/gtr.js
var require_gtr = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const outside = require_outside();
	const gtr = (version, range, options) => outside(version, range, ">", options);
	module.exports = gtr;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/ltr.js
var require_ltr = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const outside = require_outside();
	const ltr = (version, range, options) => outside(version, range, "<", options);
	module.exports = ltr;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/intersects.js
var require_intersects = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const Range = require_range();
	const intersects = (r1, r2, options) => {
		r1 = new Range(r1, options);
		r2 = new Range(r2, options);
		return r1.intersects(r2, options);
	};
	module.exports = intersects;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/simplify.js
var require_simplify = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const satisfies = require_satisfies();
	const compare = require_compare();
	module.exports = (versions, range, options) => {
		const set = [];
		let first = null;
		let prev = null;
		const v = versions.sort((a, b) => compare(a, b, options));
		for (const version of v) if (satisfies(version, range, options)) {
			prev = version;
			if (!first) first = version;
		} else {
			if (prev) set.push([first, prev]);
			prev = null;
			first = null;
		}
		if (first) set.push([first, null]);
		const ranges = [];
		for (const [min, max] of set) if (min === max) ranges.push(min);
		else if (!max && min === v[0]) ranges.push("*");
		else if (!max) ranges.push(`>=${min}`);
		else if (min === v[0]) ranges.push(`<=${max}`);
		else ranges.push(`${min} - ${max}`);
		const simplified = ranges.join(" || ");
		const original = typeof range.raw === "string" ? range.raw : String(range);
		return simplified.length < original.length ? simplified : range;
	};
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/ranges/subset.js
var require_subset = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const Range = require_range();
	const Comparator = require_comparator();
	const { ANY } = Comparator;
	const satisfies = require_satisfies();
	const compare = require_compare();
	const subset = (sub, dom, options = {}) => {
		if (sub === dom) return true;
		sub = new Range(sub, options);
		dom = new Range(dom, options);
		let sawNonNull = false;
		OUTER: for (const simpleSub of sub.set) {
			for (const simpleDom of dom.set) {
				const isSub = simpleSubset(simpleSub, simpleDom, options);
				sawNonNull = sawNonNull || isSub !== null;
				if (isSub) continue OUTER;
			}
			if (sawNonNull) return false;
		}
		return true;
	};
	const minimumVersionWithPreRelease = [new Comparator(">=0.0.0-0")];
	const minimumVersion = [new Comparator(">=0.0.0")];
	const simpleSubset = (sub, dom, options) => {
		if (sub === dom) return true;
		if (sub.length === 1 && sub[0].semver === ANY) {
			if (dom.length === 1 && dom[0].semver === ANY) return true;
			else if (options.includePrerelease) sub = minimumVersionWithPreRelease;
			else sub = minimumVersion;
		}
		if (dom.length === 1 && dom[0].semver === ANY) {
			if (options.includePrerelease) return true;
			else dom = minimumVersion;
		}
		const eqSet = /* @__PURE__ */ new Set();
		let gt, lt;
		for (const c of sub) if (c.operator === ">" || c.operator === ">=") gt = higherGT(gt, c, options);
		else if (c.operator === "<" || c.operator === "<=") lt = lowerLT(lt, c, options);
		else eqSet.add(c.semver);
		if (eqSet.size > 1) return null;
		let gtltComp;
		if (gt && lt) {
			gtltComp = compare(gt.semver, lt.semver, options);
			if (gtltComp > 0) return null;
			else if (gtltComp === 0 && (gt.operator !== ">=" || lt.operator !== "<=")) return null;
		}
		for (const eq of eqSet) {
			if (gt && !satisfies(eq, String(gt), options)) return null;
			if (lt && !satisfies(eq, String(lt), options)) return null;
			for (const c of dom) if (!satisfies(eq, String(c), options)) return false;
			return true;
		}
		let higher, lower;
		let hasDomLT, hasDomGT;
		let needDomLTPre = lt && !options.includePrerelease && lt.semver.prerelease.length ? lt.semver : false;
		let needDomGTPre = gt && !options.includePrerelease && gt.semver.prerelease.length ? gt.semver : false;
		if (needDomLTPre && needDomLTPre.prerelease.length === 1 && lt.operator === "<" && needDomLTPre.prerelease[0] === 0) needDomLTPre = false;
		for (const c of dom) {
			hasDomGT = hasDomGT || c.operator === ">" || c.operator === ">=";
			hasDomLT = hasDomLT || c.operator === "<" || c.operator === "<=";
			if (gt) {
				if (needDomGTPre) {
					if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomGTPre.major && c.semver.minor === needDomGTPre.minor && c.semver.patch === needDomGTPre.patch) needDomGTPre = false;
				}
				if (c.operator === ">" || c.operator === ">=") {
					higher = higherGT(gt, c, options);
					if (higher === c && higher !== gt) return false;
				} else if (gt.operator === ">=" && !c.test(gt.semver)) return false;
			}
			if (lt) {
				if (needDomLTPre) {
					if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomLTPre.major && c.semver.minor === needDomLTPre.minor && c.semver.patch === needDomLTPre.patch) needDomLTPre = false;
				}
				if (c.operator === "<" || c.operator === "<=") {
					lower = lowerLT(lt, c, options);
					if (lower === c && lower !== lt) return false;
				} else if (lt.operator === "<=" && !c.test(lt.semver)) return false;
			}
			if (!c.operator && (lt || gt) && gtltComp !== 0) return false;
		}
		if (gt && hasDomLT && !lt && gtltComp !== 0) return false;
		if (lt && hasDomGT && !gt && gtltComp !== 0) return false;
		if (needDomGTPre || needDomLTPre) return false;
		return true;
	};
	const higherGT = (a, b, options) => {
		if (!a) return b;
		const comp = compare(a.semver, b.semver, options);
		return comp > 0 ? a : comp < 0 ? b : b.operator === ">" && a.operator === ">=" ? b : a;
	};
	const lowerLT = (a, b, options) => {
		if (!a) return b;
		const comp = compare(a.semver, b.semver, options);
		return comp < 0 ? a : comp > 0 ? b : b.operator === "<" && a.operator === "<=" ? b : a;
	};
	module.exports = subset;
}));
// ../node_modules/.pnpm/semver@7.8.6/node_modules/semver/index.js
var require_semver = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const internalRe = require_re();
	const constants = require_constants();
	const SemVer = require_semver$1();
	const identifiers = require_identifiers();
	module.exports = {
		parse: require_parse(),
		valid: require_valid$1(),
		clean: require_clean(),
		inc: require_inc(),
		diff: require_diff(),
		major: require_major(),
		minor: require_minor(),
		patch: require_patch(),
		prerelease: require_prerelease(),
		compare: require_compare(),
		rcompare: require_rcompare(),
		compareLoose: require_compare_loose(),
		compareBuild: require_compare_build(),
		sort: require_sort(),
		rsort: require_rsort(),
		gt: require_gt(),
		lt: require_lt(),
		eq: require_eq(),
		neq: require_neq(),
		gte: require_gte(),
		lte: require_lte(),
		cmp: require_cmp(),
		coerce: require_coerce(),
		truncate: require_truncate(),
		Comparator: require_comparator(),
		Range: require_range(),
		satisfies: require_satisfies(),
		toComparators: require_to_comparators(),
		maxSatisfying: require_max_satisfying(),
		minSatisfying: require_min_satisfying(),
		minVersion: require_min_version(),
		validRange: require_valid(),
		outside: require_outside(),
		gtr: require_gtr(),
		ltr: require_ltr(),
		intersects: require_intersects(),
		simplifyRange: require_simplify(),
		subset: require_subset(),
		SemVer,
		re: internalRe.re,
		src: internalRe.src,
		tokens: internalRe.t,
		SEMVER_SPEC_VERSION: constants.SEMVER_SPEC_VERSION,
		RELEASE_TYPES: constants.RELEASE_TYPES,
		compareIdentifiers: identifiers.compareIdentifiers,
		rcompareIdentifiers: identifiers.rcompareIdentifiers
	};
}));
// src/lazy.ts
/** The `yaml` package. */
function yaml$1() {
	return import_dist;
}
/** The `semver` package. */
function semver() {
	return import_semver;
}
var import_dist, import_semver;
var init_lazy = __esmMin((() => {
	import_dist = /* @__PURE__ */ __toESM(require_dist());
	import_semver = /* @__PURE__ */ __toESM(require_semver());
}));
// ../packages/core/src/registry/resolve.ts
/** Publish time of `version` in milliseconds, or `null` if the packument has none. */
function publishTime(packument, version) {
	if (!Object.hasOwn(packument.time, version)) return null;
	const ms = Date.parse(packument.time[version] ?? "");
	return Number.isFinite(ms) ? ms : null;
}
/**
* Picks the version that `npm install name@spec` would install, or `null` when nothing
* matches. `spec` is a dist-tag, an exact version, or a semver range; `""` and `*` mean
* "latest". Ranges are parsed loosely, as npm does.
*/
function resolveVersion(packument, spec, opts = {}) {
	const { versions } = packument;
	const tags = packument["dist-tags"];
	const cutoff = opts.publishedBefore;
	const eligible = (v) => {
		if (!Object.hasOwn(versions, v)) return false;
		if (cutoff === void 0) return true;
		const at = publishTime(packument, v);
		return at !== null && at <= cutoff;
	};
	const wanted = spec.trim() === "" ? "*" : spec.trim();
	if (Object.hasOwn(tags, wanted) && semver().validRange(wanted, { loose: true }) === null) {
		const target = tags[wanted];
		return target !== void 0 && eligible(target) ? versions[target] ?? null : null;
	}
	if (semver().validRange(wanted, { loose: true }) === null) return null;
	const latest = Object.hasOwn(tags, "latest") ? tags["latest"] : void 0;
	if (latest !== void 0 && eligible(latest) && semver().satisfies(latest, wanted, { loose: true })) return versions[latest] ?? null;
	let best = null;
	for (const v of Object.keys(versions)) {
		if (!eligible(v) || semver().valid(v, { loose: true }) === null || !semver().satisfies(v, wanted, { loose: true })) continue;
		const meta = versions[v];
		if (meta === void 0) continue;
		if (best === null || better(meta, best)) best = meta;
	}
	return best;
}
function better(a, b) {
	const aDep = isDeprecated(a);
	const bDep = isDeprecated(b);
	if (aDep !== bDep) return bDep;
	return semver().gt(a.version, b.version, { loose: true });
}
/** True for a valid semver version with a prerelease tag (`1.0.0-beta.1`). */
function isPrerelease(version) {
	return (semver().prerelease(version, { loose: true })?.length ?? 0) > 0;
}
/** True when the version carries a non-empty `deprecated` message. */
function isDeprecated(meta) {
	return typeof meta.deprecated === "string" && meta.deprecated !== "";
}
var init_resolve = __esmMin((() => {
	init_lazy();
}));
// ../packages/core/src/registry/history.ts
/**
* Versions published before `version`, newest first, optionally only those that pass
* `keep`. Versions without a time are skipped.
*/
function previousVersions(packument, version, limit = 5, keep = () => true) {
	const at = publishTime(packument, version);
	if (at === null) return [];
	return timed(packument).filter((t) => t.at < at && t.meta.version !== version && keep(t.meta)).toSorted((a, b) => b.at - a.at).slice(0, limit).map((t) => t.meta);
}
function timed(packument) {
	const out = [];
	for (const [v, meta] of Object.entries(packument.versions)) {
		const at = publishTime(packument, v);
		if (at !== null) out.push({
			meta,
			at
		});
	}
	return out;
}
function personName(p) {
	return typeof p === "object" && p !== null && typeof p.name === "string" && p.name !== "" ? p.name : null;
}
function maintainerNames(meta) {
	if (!Array.isArray(meta.maintainers)) return null;
	const names = /* @__PURE__ */ new Set();
	for (const m of meta.maintainers) {
		const n = personName(m);
		if (n !== null) names.add(n);
	}
	return names;
}
/** True when the version's `dist` advertises attestations. */
function hasAttestations(meta) {
	const a = meta.dist.attestations;
	return typeof a === "object" && a !== null && typeof a.url === "string";
}
/**
* True when the version was published through npm trusted publishing (OIDC) and has a
* provenance attestation. The registry sets `_npmUser` itself, adding
* `trustedPublisher: { id: "github" | …, oidcConfigId }` to such publishes (observed on
* registry.npmjs.org, 2026-11-11: es-module-lexer@3.0.4, tar@7.5.23; trusted publishing
* generates provenance, https://docs.npmjs.com/trusted-publishers). A name or email
* alone is never enough: an ordinary account can be called "GitHub Actions".
*/
function isTrustedPublish(meta) {
	const user = meta._npmUser;
	if (typeof user !== "object" || user === null) return false;
	const tp = user.trustedPublisher;
	if (typeof tp !== "object" || tp === null || typeof tp.id !== "string") return false;
	const provenance = meta.dist.attestations?.provenance;
	return hasAttestations(meta) && typeof provenance === "object" && provenance !== null;
}
/**
* `publisher-changed`: the version's `_npmUser` did not publish any of the previous
* {@link HISTORY_WINDOW} versions and is not an established maintainer. `null`
* otherwise, or when there is no history to compare with.
*
* Established means listed in the `maintainers` of the version just before this one
* *and* of the newest version published at least {@link ESTABLISHED_MAINTAINER_DAYS}
* days before it. Each version records its maintainers as they were at publish time,
* so an account an attacker added recently never qualifies, even if a release in
* between already lists it. A long-standing maintainer publishing for the first time
* (a team member, or a CI account) is not flagged.
*
* Also not flagged (approved 2026-11-11 after the top-1,000 benchmark):
* - a version published through npm trusted publishing with a provenance attestation
*   ({@link isTrustedPublish}). Moving to OIDC publishing replaces the person in
*   `_npmUser` with the CI identity, and a maintainer has to set it up on npmjs.com.
* - with `now`, a version published more than {@link PUBLISHER_CHANGE_MAX_AGE_DAYS} days
*   ago: a takeover shows up in a fresh release, and an old one has been in use since.
*/
function publisherChange(packument, meta, opts = {}) {
	const publisher = personName(meta._npmUser);
	if (publisher === null || isTrustedPublish(meta)) return null;
	if (opts.now !== void 0) {
		const at = publishTime(packument, meta.version);
		if (at !== null && opts.now - at > 90 * DAY$1) return null;
	}
	const history = previousVersions(packument, meta.version);
	const previous = [...new Set(history.map((m) => personName(m._npmUser)).filter((n) => n !== null))];
	if (previous.length === 0 || previous.includes(publisher)) return null;
	return isEstablishedMaintainer(packument, meta, publisher, history[0]) ? null : {
		publisher,
		previous
	};
}
function isEstablishedMaintainer(packument, meta, name, last) {
	const at = publishTime(packument, meta.version);
	if (at === null || last === void 0 || !maintainerNames(last)?.has(name)) return false;
	const cutoff = at - 30 * DAY$1;
	const baseline = timed(packument).filter((t) => t.at <= cutoff).toSorted((a, b) => b.at - a.at)[0];
	return baseline !== void 0 && maintainerNames(baseline.meta)?.has(name) === true;
}
/**
* `maintainer-added-recently`: maintainers listed on versions published within the
* last `days` days who are not listed on the newest version published before that
* window. Empty when the package has no version older than the window (it is new,
* which `package-too-new` covers) or when that version records no maintainers.
*/
function addedMaintainers(packument, now, days = 30) {
	const cutoff = now - days * DAY$1;
	const all = timed(packument).toSorted((a, b) => a.at - b.at);
	const baseline = all.filter((t) => t.at < cutoff).at(-1);
	const known = baseline ? maintainerNames(baseline.meta) : null;
	if (known === null) return [];
	const added = [];
	for (const t of all) {
		if (t.at < cutoff || t.at > now) continue;
		for (const name of maintainerNames(t.meta) ?? []) {
			if (known.has(name)) continue;
			known.add(name);
			added.push({
				name,
				version: t.meta.version
			});
		}
	}
	return added;
}
/**
* `provenance-dropped`: the version has no attestations, but one of the previous
* {@link HISTORY_WINDOW} versions did. Returns that earlier version, or `null`.
*
* A stable version is compared only with earlier stable versions: projects often build
* prereleases (`8.0.0-alpha.14`) on a different pipeline than their stable line, and a
* stable line that never had provenance hasn't dropped it. A prerelease is compared
* with every earlier version, so dropping provenance on either line is still caught.
*/
function provenanceDrop(packument, meta) {
	if (hasAttestations(meta)) return null;
	const sameLine = isPrerelease(meta.version) ? () => true : (m) => !isPrerelease(m.version);
	return previousVersions(packument, meta.version, 5, sameLine).find(hasAttestations) ?? null;
}
var DAY$1;
var init_history = __esmMin((() => {
	init_resolve();
	DAY$1 = 864e5;
}));
// ../packages/core/src/tar.ts
/**
* Reads a package tarball in memory. Accepts gzip'd or plain tar. Throws a
* {@link DepwardError} with `LIMIT_EXCEEDED`, `INVALID_ARCHIVE`, or `UNSAFE_PATH`
* (absolute paths, `..`, or links that point outside the package).
*
* Verify integrity first ({@link verifyIntegrity}; `RegistryClient.tarball` already does).
*/
function readTarball(bytes, limits = {}) {
	const maxCompressed = limits.maxCompressedBytes ?? 52428800;
	const maxUncompressed = limits.maxUncompressedBytes ?? 209715200;
	const maxEntries = limits.maxEntries ?? 2e4;
	if (bytes.byteLength > maxCompressed) throw tooBig("compressed size");
	const tarBytes = bytes[0] === 31 && bytes[1] === 139 ? gunzip(bytes, maxUncompressed) : bytes;
	if (tarBytes.byteLength > maxUncompressed) throw tooBig("uncompressed size");
	const files = /* @__PURE__ */ new Map();
	const links = /* @__PURE__ */ new Map();
	const duplicates = /* @__PURE__ */ new Set();
	let entries = 0;
	let pending = {};
	for (let offset = 0; offset + BLOCK <= tarBytes.byteLength;) {
		const h = tarBytes.subarray(offset, offset + BLOCK);
		if (h.every((b) => b === 0)) break;
		if (++entries > maxEntries) throw tooBig("entry count");
		verifyChecksum(h);
		const type = String.fromCharCode(h[156] ?? 0);
		const size = parseSize(h.subarray(124, 136), maxUncompressed);
		const dataStart = offset + BLOCK;
		const dataEnd = dataStart + size;
		if (dataEnd > tarBytes.byteLength) throw invalid$1("entry data is truncated");
		const data = tarBytes.subarray(dataStart, dataEnd);
		offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
		if (type === "x" || type === "L" || type === "K") {
			if (size > MAX_META_BYTES) throw tooBig("metadata header size");
			if (type === "x") pending = {
				...pending,
				...parsePax(data)
			};
			else if (type === "L") pending.path = cString(data);
			else pending.linkpath = cString(data);
			continue;
		}
		if (type === "g") continue;
		const rawPath = pending.path ?? headerPath(h);
		const rawLink = pending.linkpath ?? cString(h.subarray(157, 257));
		pending = {};
		const path = packagePath(rawPath);
		if (path === null) continue;
		if (type === "0" || type === "\0" || type === "7") {
			if (files.has(path) || links.has(path)) duplicates.add(path);
			links.delete(path);
			files.set(path, {
				path,
				mode: parseOctal(h.subarray(100, 108)) & 4095,
				data: data.slice()
			});
		} else if (type === "1" || type === "2") {
			const kind = type === "2" ? "symlink" : "hardlink";
			const target = kind === "symlink" ? checkSymlink(path, rawLink) : checkHardlink(rawLink);
			if (files.has(path) || links.has(path)) duplicates.add(path);
			files.delete(path);
			links.set(path, {
				path,
				target,
				kind
			});
		}
	}
	const fileList = sorted(files);
	return {
		files: fileList,
		links: sorted(links),
		duplicates: [...duplicates].toSorted(),
		unpackedSize: fileList.reduce((n, f) => n + f.data.byteLength, 0)
	};
}
function sorted(m) {
	return [...m.values()].toSorted((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
function gunzip(bytes, maxOutputLength) {
	try {
		return gunzipSync(bytes, { maxOutputLength });
	} catch (err) {
		if (err.code === "ERR_BUFFER_TOO_LARGE") throw tooBig("uncompressed size");
		throw new DepwardError("INVALID_ARCHIVE", "invalid tarball: gzip stream is corrupt", { cause: err });
	}
}
function verifyChecksum(h) {
	const stored = parseOctal(h.subarray(148, 156));
	let unsigned = 0;
	let signed = 0;
	for (let i = 0; i < BLOCK; i++) {
		const b = i >= 148 && i < 156 ? 32 : h[i] ?? 0;
		unsigned += b;
		signed += b > 127 ? b - 256 : b;
	}
	if (stored !== unsigned && stored !== signed) throw invalid$1("header checksum mismatch");
}
function cString(bytes) {
	const nul = bytes.indexOf(0);
	return new TextDecoder().decode(nul < 0 ? bytes : bytes.subarray(0, nul));
}
function parseOctal(field) {
	const s = cString(field).trim();
	if (s === "") return 0;
	if (!/^[0-7]+$/.test(s)) throw invalid$1("malformed numeric field");
	return Number.parseInt(s, 8);
}
/** Size field: octal, or GNU base-256 when the high bit of the first byte is set. */
function parseSize(field, max) {
	if (((field[0] ?? 0) & 128) === 0) {
		const n = parseOctal(field);
		if (n > max) throw tooBig("uncompressed size");
		return n;
	}
	if ((field[0] ?? 0) & 64) throw invalid$1("negative size");
	let n = (field[0] ?? 0) & 127;
	for (let i = 1; i < field.length; i++) {
		n = n * 256 + (field[i] ?? 0);
		if (n > max) throw tooBig("uncompressed size");
	}
	return n;
}
function headerPath(h) {
	const name = cString(h.subarray(0, 100));
	const prefix = cString(h.subarray(257, 263)) === "ustar" && h[262] === 0 ? cString(h.subarray(345, 500)) : "";
	return prefix ? `${prefix}/${name}` : name;
}
/** Parses pax records (`"<len> key=value\n"`), keeping only `path` and `linkpath`. */
function parsePax(data) {
	const out = {};
	let i = 0;
	while (i < data.byteLength) {
		const space = data.indexOf(32, i);
		if (space < 0) break;
		const len = Number(new TextDecoder().decode(data.subarray(i, space)));
		if (!Number.isInteger(len) || len <= space - i || i + len > data.byteLength) throw invalid$1("malformed pax header");
		const record = new TextDecoder().decode(data.subarray(space + 1, i + len - 1));
		const eq = record.indexOf("=");
		if (eq > 0) {
			const key = record.slice(0, eq);
			if (key === "path" || key === "linkpath") out[key] = record.slice(eq + 1);
		}
		i += len;
	}
	return out;
}
/** Splits on `/` and `\`, rejecting NUL, absolute paths, drive letters, and `..`. */
function safeSegments(raw, what) {
	if (raw.includes("\0")) throw unsafe(`${what} contains NUL`);
	if (/^(?:[/\\]|[A-Za-z]:)/.test(raw)) throw unsafe(`${what} is absolute`);
	const segs = raw.split(/[/\\]/).filter((s) => s !== "" && s !== ".");
	if (segs.includes("..")) throw unsafe(`${what} contains ".."`);
	return segs;
}
/** Package-relative path (first segment, usually `package/`, removed), or `null` for the root. */
function packagePath(raw) {
	const segs = safeSegments(raw, "path");
	return segs.length > 1 ? segs.slice(1).join("/") : null;
}
function checkSymlink(path, target) {
	if (target.includes("\0")) throw unsafe("symlink target contains NUL");
	if (/^(?:[/\\]|[A-Za-z]:)/.test(target)) throw unsafe("symlink target is absolute");
	const resolved = posix.normalize(posix.join(posix.dirname(path), target.replaceAll("\\", "/")));
	if (resolved === ".." || resolved.startsWith("../")) throw unsafe("symlink points outside the package");
	return target;
}
function checkHardlink(target) {
	const path = packagePath(target);
	if (path === null) throw unsafe("hardlink target is not a package file");
	return path;
}
var BLOCK, MAX_META_BYTES, tooBig, invalid$1, unsafe;
var init_tar = __esmMin((() => {
	init_errors();
	BLOCK = 512;
	MAX_META_BYTES = 1048576;
	tooBig = (what) => new DepwardError("LIMIT_EXCEEDED", `tarball exceeds the ${what} limit`);
	invalid$1 = (why) => new DepwardError("INVALID_ARCHIVE", `invalid tarball: ${why}`);
	unsafe = (why) => new DepwardError("UNSAFE_PATH", `unsafe tarball entry: ${why}`);
}));
// ../packages/core/src/lockfile/types.ts
function invalidLockfile(path, why, cause) {
	return new DepwardError("INVALID_LOCKFILE", `${path}: ${why}`, cause === void 0 ? void 0 : { cause });
}
function isRecord$1(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Own entries of a record-like value; empty for anything else. */
function entriesOf(value) {
	return isRecord$1(value) ? Object.entries(value) : [];
}
function str(value) {
	return typeof value === "string" && value !== "" ? value : null;
}
/** Splits `name@ref` (scoped names keep their leading `@`). */
function splitIdent(ident) {
	const at = ident.indexOf("@", 1);
	if (at <= 0) return null;
	return {
		name: ident.slice(0, at),
		ref: ident.slice(at + 1)
	};
}
/** True for a plain semver version (what registries publish). */
function isSemver(s) {
	return SEMVER.test(s);
}
/** Classifies a dependency reference or resolution string. */
function classifyRef(ref) {
	if (ref.startsWith("workspace:")) return "workspace";
	if (ref.startsWith("link:") || ref.startsWith("portal:")) return "link";
	if (ref.startsWith("file:") || /^\.{0,2}\//.test(ref) || /\.(?:tgz|tar\.gz|tar)$/.test(ref) && !/^https?:/.test(ref)) return "file";
	if (ref.startsWith("patch:") || ref.startsWith("exec:")) return "other";
	if (/^(?:git\+|git:|git@|github:|gitlab:|bitbucket:)/.test(ref) || ref.startsWith("https://codeload.github.com/") || ref.startsWith("github.com/") || /\.git(?:#|$)/.test(ref)) return "git";
	if (/^https?:\/\//.test(ref)) return "tarball";
	return "registry";
}
/**
* Adds an entry, merging duplicates (the same `name@version` installed at several paths):
* the merged package is dev/optional only if every copy is.
*/
function addEntry(entries, entry) {
	const key = `${entry.name}@${entry.version}`;
	const prev = entries.get(key);
	if (!prev) {
		entries.set(key, entry);
		return;
	}
	prev.dev = andNullable(prev.dev, entry.dev);
	prev.optional = andNullable(prev.optional, entry.optional);
	prev.integrity ??= entry.integrity;
	prev.resolved ??= entry.resolved;
}
function andNullable(a, b) {
	if (a === null) return b;
	if (b === null) return a;
	return a && b;
}
/** Returns a new map with keys in code-unit order, for deterministic output. */
function sortedEntries(entries) {
	return new Map([...entries].toSorted(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
}
var SEMVER;
var init_types$1 = __esmMin((() => {
	init_errors();
	SEMVER = /^v?\d+\.\d+\.\d+(?:[-+][\w.+-]*)?$/;
}));
// ../packages/core/src/lockfile/bun.ts
function parseBun(doc) {
	const entries = /* @__PURE__ */ new Map();
	for (const [, tuple] of entriesOf(doc["packages"])) {
		if (!Array.isArray(tuple)) continue;
		const ident = typeof tuple[0] === "string" ? splitIdent(tuple[0]) : null;
		if (!ident || ident.ref.startsWith("root:")) continue;
		const { name, ref } = ident;
		const isRegistry = isSemver(ref);
		const source = isRegistry ? "registry" : classifyRef(ref);
		addEntry(entries, {
			name,
			version: ref,
			source,
			integrity: isRegistry ? str(tuple[3]) : source === "tarball" || source === "file" ? sri(tuple[2]) : null,
			resolved: isRegistry ? null : ref,
			dev: null,
			optional: null
		});
	}
	return entries;
}
function sri(value) {
	const s = str(value);
	return s && /^sha(?:1|256|384|512)-/.test(s) ? s : null;
}
/**
* Parses JSONC: JSON plus `//` and `/* *\/` comments and trailing commas. Strings are
* copied verbatim, so comment-like text inside them is preserved.
*/
function parseJsonc(text) {
	let out = "";
	let i = 0;
	while (i < text.length) {
		const c = text[i];
		if (c === "\"") {
			let j = i + 1;
			while (j < text.length && text[j] !== "\"") j += text[j] === "\\" ? 2 : 1;
			out += text.slice(i, j + 1);
			i = j + 1;
		} else if (c === "/" && text[i + 1] === "/") while (i < text.length && text[i] !== "\n") i++;
		else if (c === "/" && text[i + 1] === "*") {
			const end = text.indexOf("*/", i + 2);
			i = end < 0 ? text.length : end + 2;
		} else if (c === ",") {
			let j = i + 1;
			for (;;) {
				while (j < text.length && /\s/.test(text[j] ?? "")) j++;
				if (text.startsWith("//", j)) j = text.indexOf("\n", j) < 0 ? text.length : text.indexOf("\n", j);
				else if (text.startsWith("/*", j)) j = text.indexOf("*/", j + 2) < 0 ? text.length : text.indexOf("*/", j + 2) + 2;
				else break;
			}
			if (text[j] !== "}" && text[j] !== "]") out += ",";
			i++;
		} else {
			out += c;
			i++;
		}
	}
	return JSON.parse(out);
}
var init_bun = __esmMin((() => {
	init_types$1();
}));
// ../packages/core/src/lockfile/npm.ts
/** Parses the `packages` map. Returns `null` for lockfileVersion 1 (unsupported). */
function parseNpm(doc) {
	const lockfileVersion = doc["lockfileVersion"];
	if (typeof lockfileVersion !== "number" || lockfileVersion < 2 || !isRecord$1(doc["packages"])) return null;
	const packages = doc["packages"];
	const root = isRecord$1(packages[""]) ? packages[""] : {};
	const workspaceGlobs = (Array.isArray(root["workspaces"]) ? root["workspaces"] : []).filter((g) => typeof g === "string").map(globToRegExp$1);
	const entries = /* @__PURE__ */ new Map();
	for (const [key, raw] of entriesOf(packages)) {
		const idx = key.lastIndexOf(NM);
		if (idx < 0 || !isRecord$1(raw)) continue;
		const installName = key.slice(idx + 13);
		const name = str(raw["name"]) ?? installName;
		const resolved = str(raw["resolved"]);
		const integrity = str(raw["integrity"]);
		const flags = {
			dev: raw["dev"] === true,
			optional: raw["optional"] === true
		};
		if (raw["link"] === true) {
			const target = resolved ?? "";
			const targetMeta = packages[target];
			const targetVersion = isRecord$1(targetMeta) ? str(targetMeta["version"]) : null;
			const isWorkspace = workspaceGlobs.some((re) => re.test(target));
			addEntry(entries, {
				name,
				version: targetVersion ?? `link:${target}`,
				source: isWorkspace ? "workspace" : "link",
				integrity: null,
				resolved,
				...flags
			});
			continue;
		}
		const version = str(raw["version"]) ?? resolved ?? "";
		let source = raw["inBundle"] === true ? "bundled" : resolved ? classifyRef(resolved) : "registry";
		if (source === "tarball" && isSemver(version) && integrity && resolved?.includes("/-/")) source = "registry";
		addEntry(entries, {
			name,
			version,
			source,
			integrity,
			resolved,
			...flags
		});
	}
	return entries;
}
/** Minimal workspace glob support: `*` within a segment, `**` across segments. */
function globToRegExp$1(glob) {
	const body = glob.replace(/^\.\//, "").replace(/\/$/, "").split(/(\*\*|\*)/).map((part) => part === "**" ? ".*" : part === "*" ? "[^/]*" : part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("");
	return new RegExp(`^${body}$`);
}
var NM;
var init_npm = __esmMin((() => {
	init_types$1();
	NM = "node_modules/";
}));
// ../packages/core/src/lockfile/pnpm.ts
/** Returns `null` for unsupported lockfile versions (below 6, or above 9). */
function parsePnpm(doc) {
	const major = Math.trunc(Number.parseFloat(String(doc["lockfileVersion"] ?? "")));
	if (major !== 6 && major !== 9) return null;
	const v9 = major === 9;
	const importers = importersOf(doc);
	const entries = /* @__PURE__ */ new Map();
	const reach = v9 ? walkSnapshots(doc, importers) : null;
	const snapshotOptional = v9 ? optionalByPackage(doc) : null;
	for (const [key, raw] of entriesOf(doc["packages"])) {
		if (!isRecord$1(raw)) continue;
		const id = stripPeers(v9 ? key : key.replace(/^\//, ""));
		const ident = splitIdent(id);
		const name = str(raw["name"]) ?? ident?.name;
		if (!name) continue;
		const ref = ident && ident.name === name ? ident.ref : id;
		const version = str(raw["version"]) ?? ref;
		const resolution = isRecord$1(raw["resolution"]) ? raw["resolution"] : {};
		let dev;
		let optional;
		if (reach) {
			dev = reach.prod.has(id) ? false : reach.dev.has(id) ? true : null;
			optional = snapshotOptional?.get(id) ?? false;
		} else {
			dev = raw["dev"] === true;
			optional = raw["optional"] === true;
		}
		addEntry(entries, {
			name,
			version,
			source: sourceOf(ref, resolution),
			integrity: str(resolution["integrity"]),
			resolved: str(resolution["tarball"]) ?? str(resolution["repo"]) ?? str(resolution["directory"]),
			dev,
			optional
		});
	}
	for (const [, deps] of importers) for (const [field, map] of deps) for (const [name, version] of map) {
		if (!version.startsWith("link:")) continue;
		addEntry(entries, {
			name,
			version,
			source: "link",
			integrity: null,
			resolved: version.slice(5),
			dev: field === "devDependencies",
			optional: field === "optionalDependencies"
		});
	}
	return entries;
}
function stripPeers(id) {
	const paren = id.indexOf("(");
	return paren < 0 ? id : id.slice(0, paren);
}
function sourceOf(ref, resolution) {
	if (resolution["type"] === "git" || resolution["gitHosted"] === true) return "git";
	if (resolution["type"] === "directory") return "file";
	if (isSemver(ref)) return "registry";
	return classifyRef(ref);
}
/** Importers as `path → field → name → version`. v6 single-project files keep deps at the top level. */
function importersOf(doc) {
	const out = /* @__PURE__ */ new Map();
	const read = (src) => {
		const maps = /* @__PURE__ */ new Map();
		for (const field of [...PROD_ROOT_FIELDS, "devDependencies"]) {
			const m = /* @__PURE__ */ new Map();
			for (const [name, val] of entriesOf(src[field])) {
				const version = isRecord$1(val) ? str(val["version"]) : str(val);
				if (version) m.set(name, version);
			}
			maps.set(field, m);
		}
		return maps;
	};
	if (isRecord$1(doc["importers"])) {
		for (const [path, imp] of entriesOf(doc["importers"])) if (isRecord$1(imp)) out.set(path, read(imp));
	} else out.set(".", read(doc));
	return out;
}
/** v9: which package ids are reachable from prod roots, and which from dev roots. */
function walkSnapshots(doc, importers) {
	const snapshots = new Map(entriesOf(doc["snapshots"]));
	const resolve = (name, value) => {
		if (snapshots.has(`${name}@${value}`)) return `${name}@${value}`;
		if (snapshots.has(value)) return value;
		return null;
	};
	const walk = (roots) => {
		const seen = /* @__PURE__ */ new Set();
		const stack = [...roots];
		while (stack.length > 0) {
			const key = stack.pop();
			if (seen.has(key)) continue;
			seen.add(key);
			const snap = snapshots.get(key);
			if (!isRecord$1(snap)) continue;
			for (const field of DEP_FIELDS) for (const [n, v] of entriesOf(snap[field])) {
				const next = typeof v === "string" ? resolve(n, v) : null;
				if (next && !seen.has(next)) stack.push(next);
			}
		}
		return new Set([...seen].map(stripPeers));
	};
	const rootsFor = (fields) => {
		const roots = [];
		for (const [, maps] of importers) for (const field of fields) for (const [name, version] of maps.get(field) ?? []) {
			const key = resolve(name, version);
			if (key) roots.push(key);
		}
		return roots;
	};
	return {
		prod: walk(rootsFor(PROD_ROOT_FIELDS)),
		dev: walk(rootsFor(["devDependencies"]))
	};
}
/** v9: a package is optional only if every snapshot of it is. */
function optionalByPackage(doc) {
	const out = /* @__PURE__ */ new Map();
	for (const [key, snap] of entriesOf(doc["snapshots"])) {
		const id = stripPeers(key);
		const optional = isRecord$1(snap) && snap["optional"] === true;
		out.set(id, (out.get(id) ?? true) && optional);
	}
	return out;
}
var DEP_FIELDS, PROD_ROOT_FIELDS;
var init_pnpm = __esmMin((() => {
	init_types$1();
	DEP_FIELDS = ["dependencies", "optionalDependencies"];
	PROD_ROOT_FIELDS = [
		"dependencies",
		"optionalDependencies",
		"packageManagerDependencies",
		"configDependencies"
	];
}));
// ../packages/core/src/lockfile/yarn-berry.ts
function parseYarnBerry(doc) {
	const entries = /* @__PURE__ */ new Map();
	for (const [key, raw] of entriesOf(doc)) {
		if (key === "__metadata" || !isRecord$1(raw)) continue;
		const resolution = str(raw["resolution"]);
		const ident = resolution ? splitIdent(resolution) : null;
		if (!ident) continue;
		if (ident.ref === "workspace:.") continue;
		const source = berrySource(ident.ref);
		addEntry(entries, {
			name: ident.name,
			version: str(raw["version"]) ?? ident.ref,
			source,
			integrity: null,
			resolved: source === "registry" ? null : ident.ref,
			dev: null,
			optional: null
		});
	}
	return entries;
}
function berrySource(ref) {
	if (ref.startsWith("npm:")) return "registry";
	return classifyRef(ref);
}
var init_yarn_berry = __esmMin((() => {
	init_types$1();
}));
// ../packages/core/src/lockfile/yarn-classic.ts
/** Parses a yarn v1 lockfile. Throws a plain `Error` on syntax errors (wrapped by the caller). */
function parseYarnClassic(text) {
	const entries = /* @__PURE__ */ new Map();
	for (const block of blocks(text)) {
		const first = block.specs[0];
		const parsed = first ? splitIdent(first) : null;
		const version = block.fields.get("version");
		if (!parsed || !version) continue;
		let { name, ref } = parsed;
		if (ref.startsWith("npm:")) {
			const real = splitIdent(ref.slice(4));
			if (real) ({name, ref} = real);
			else ref = ref.slice(4);
		}
		const rawResolved = block.fields.get("resolved") ?? null;
		let source = classifyRef(ref);
		if (source === "registry" && rawResolved && classifyRef(rawResolved) === "git") source = "git";
		addEntry(entries, {
			name,
			version,
			source,
			integrity: block.fields.get("integrity") ?? null,
			resolved: rawResolved?.replace(/(\.tgz)#[0-9a-f]{40}$/, "$1") ?? null,
			dev: null,
			optional: null
		});
	}
	return entries;
}
function* blocks(text) {
	let current = null;
	let lineNo = 0;
	for (const rawLine of text.split(/\r?\n/)) {
		lineNo++;
		if (rawLine.trim() === "" || rawLine.trimStart().startsWith("#")) continue;
		const indent = rawLine.length - rawLine.trimStart().length;
		const line = rawLine.trim();
		if (indent === 0) {
			if (current) yield current;
			if (!line.endsWith(":")) throw new Error(`line ${lineNo}: expected "<specs>:"`);
			current = {
				specs: tokens(line.slice(0, -1), lineNo).filter((t) => t !== ","),
				fields: /* @__PURE__ */ new Map()
			};
		} else if (indent === 2 && current) {
			if (line.endsWith(":")) continue;
			const [key, value] = tokens(line, lineNo);
			if (key !== void 0 && value !== void 0) current.fields.set(key, value);
		} else if (!current) throw new Error(`line ${lineNo}: unexpected indentation`);
	}
	if (current) yield current;
}
/** Splits a line into tokens: double-quoted strings (JSON escapes), commas, and bare words. */
function tokens(line, lineNo) {
	const out = [];
	let i = 0;
	while (i < line.length) {
		const c = line[i];
		if (c === " " || c === "	") i++;
		else if (c === ",") {
			out.push(",");
			i++;
		} else if (c === "\"") {
			let j = i + 1;
			while (j < line.length && line[j] !== "\"") j += line[j] === "\\" ? 2 : 1;
			if (j >= line.length) throw new Error(`line ${lineNo}: unterminated string`);
			out.push(JSON.parse(line.slice(i, j + 1)));
			i = j + 1;
		} else {
			let j = i;
			while (j < line.length && !/[\s,]/.test(line[j] ?? "")) j++;
			out.push(line.slice(i, j));
			i = j;
		}
	}
	return out.flatMap((t) => t !== "," && t.endsWith(",") ? [t.slice(0, -1), ","] : [t]);
}
var init_yarn_classic = __esmMin((() => {
	init_types$1();
}));
// ../packages/core/src/lockfile/index.ts
/**
* Parses a lockfile into normalized `name@version` entries. The format is chosen by file
* name (and, for `yarn.lock`, by content). Recognized but unsupported formats (npm
* lockfileVersion 1, pnpm < 6, binary `bun.lockb`) return no entries and an
* `unsupported-lockfile` finding.
*
* @throws DepwardError `INVALID_ARGUMENT` for an unknown file name, `INVALID_LOCKFILE`
*   when the contents cannot be parsed, `LIMIT_EXCEEDED` above `maxBytes`.
*/
function parseLockfile(path, contents, opts = {}) {
	const base = path.split(/[/\\]/).pop() ?? "";
	if (!KNOWN.has(base)) throw new DepwardError("INVALID_ARGUMENT", `not a known lockfile name: ${base}`);
	if (contents.length > (opts.maxBytes ?? 104857600)) throw new DepwardError("LIMIT_EXCEEDED", `${path} is larger than the lockfile size limit`);
	const done = (format, entries, detail) => entries ? {
		path,
		format,
		entries: sortedEntries(entries),
		findings: []
	} : unsupported(path, detail);
	switch (base) {
		case "package-lock.json":
		case "npm-shrinkwrap.json": return done("npm", parseNpm(asObject(path, () => JSON.parse(contents))), "npm lockfileVersion 1 is not supported; run npm 7+ to upgrade it");
		case "pnpm-lock.yaml": {
			const merged = /* @__PURE__ */ new Map();
			for (const doc of tryParse(path, () => yamlDocuments(contents))) {
				const entries = parsePnpm(checkObject(path, doc));
				if (!entries) return unsupported(path, "only pnpm lockfileVersion 6.x and 9.x are supported");
				for (const entry of entries.values()) addEntry(merged, entry);
			}
			return done("pnpm", merged, "");
		}
		case "bun.lock": return done("bun", parseBun(asObject(path, () => parseJsonc(contents))), "");
		case "bun.lockb": return unsupported(path, "the binary bun.lockb format is not supported; run `bun install --save-text-lockfile`");
		default: {
			if (/^# yarn lockfile v1\s*$/m.test(contents)) return done("yarn-classic", tryParse(path, () => parseYarnClassic(contents)), "");
			const doc = asObject(path, () => yaml(contents));
			if (!isRecord$1(doc["__metadata"])) throw invalidLockfile(path, "yarn.lock is neither yarn v1 nor yarn berry");
			return done("yarn-berry", parseYarnBerry(doc), "");
		}
	}
}
function yaml(text) {
	return yaml$1().parse(text, {
		maxAliasCount: MAX_ALIASES,
		uniqueKeys: false
	});
}
function yamlDocuments(text) {
	const docs = yaml$1().parseAllDocuments(text, { uniqueKeys: false });
	if (!Array.isArray(docs) || docs.length === 0) throw new Error("no YAML documents");
	return docs.map((doc) => {
		const [error] = doc.errors;
		if (error) throw error;
		return doc.toJS({ maxAliasCount: MAX_ALIASES });
	});
}
function tryParse(path, parse) {
	try {
		return parse();
	} catch (cause) {
		throw invalidLockfile(path, "could not be parsed", cause);
	}
}
function asObject(path, parse) {
	return checkObject(path, tryParse(path, parse));
}
function checkObject(path, doc) {
	if (!isRecord$1(doc)) throw invalidLockfile(path, "top level is not an object");
	for (const key of [
		"packages",
		"snapshots",
		"importers"
	]) if (key in doc && doc[key] !== null && !isRecord$1(doc[key])) throw invalidLockfile(path, `"${key}" is not an object`);
	return doc;
}
function unsupported(path, detail) {
	const finding = {
		id: "unsupported-lockfile",
		severity: "info",
		package: path,
		message: `${path} uses a lockfile format depward cannot read, so its dependencies were not checked`,
		evidence: detail ? [{
			file: path,
			detail
		}] : [{ file: path }],
		docsUrl: findingDocsUrl("unsupported-lockfile")
	};
	return {
		path,
		format: null,
		entries: /* @__PURE__ */ new Map(),
		findings: [finding]
	};
}
/**
* Compares two lockfiles. Fields one side does not record (`null`) are not compared, so
* switching package managers does not report every entry as changed. When neither side
* has integrity, a different `resolved` (for example a new git commit) counts as a change.
*/
function diffLockfiles(base, head) {
	const added = [];
	const removed = [];
	const changed = [];
	for (const [key, after] of head.entries) {
		const before = base.entries.get(key);
		if (!before) added.push(after);
		else if (entryChanged(before, after)) changed.push({
			before,
			after
		});
	}
	for (const [key, before] of base.entries) if (!head.entries.has(key)) removed.push(before);
	return {
		added: added.toSorted(byKey),
		removed: removed.toSorted(byKey),
		changed: changed.toSorted((x, y) => byKey(x.after, y.after))
	};
}
function byKey(a, b) {
	const ka = `${a.name}@${a.version}`;
	const kb = `${b.name}@${b.version}`;
	return ka < kb ? -1 : ka > kb ? 1 : 0;
}
/** True when both sides record a value and the values differ. */
function differs(x, y) {
	return x !== null && y !== null && x !== y;
}
function entryChanged(a, b) {
	if (a.source !== b.source) return true;
	if (differs(a.integrity, b.integrity)) return true;
	if (a.integrity === null && b.integrity === null && differs(a.resolved, b.resolved)) return true;
	return differs(a.dev, b.dev) || differs(a.optional, b.optional);
}
var KNOWN_LOCKFILES, KNOWN, MAX_ALIASES;
var init_lockfile = __esmMin((() => {
	init_lazy();
	init_errors();
	init_findings();
	init_bun();
	init_npm();
	init_pnpm();
	init_types$1();
	init_yarn_berry();
	init_yarn_classic();
	KNOWN_LOCKFILES = [
		"package-lock.json",
		"npm-shrinkwrap.json",
		"pnpm-lock.yaml",
		"yarn.lock",
		"bun.lock",
		"bun.lockb"
	];
	KNOWN = new Set(KNOWN_LOCKFILES);
	MAX_ALIASES = 50;
}));
// ../packages/core/src/git.ts
function git(args, cwd, opts) {
	return new Promise((resolve, reject) => {
		execFile("git", args, {
			cwd,
			encoding: "utf8",
			maxBuffer: opts.maxBytes,
			timeout: opts.timeoutMs,
			windowsHide: true,
			env: {
				...process.env,
				GIT_TERMINAL_PROMPT: "0",
				GIT_OPTIONAL_LOCKS: "0"
			}
		}, (err, stdout, stderr) => {
			if (!err) return resolve({
				ok: true,
				stdout,
				stderr
			});
			const code = err.code;
			if (code === "ENOENT") return reject(new DepwardError("GIT", "git is not installed or not on PATH", { cause: err }));
			if (code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return reject(new DepwardError("LIMIT_EXCEEDED", "file at ref is larger than the size limit", { cause: err }));
			if (err.killed) return reject(new DepwardError("TIMEOUT", "git timed out", { cause: err }));
			resolve({
				ok: false,
				stdout,
				stderr
			});
		});
	});
}
/**
* Reads `path` (relative to `cwd`) as it was at git `ref`, like `git show <ref>:<path>`.
* Returns `null` when the file does not exist at that ref.
*
* @throws DepwardError `INVALID_ARGUMENT` for a malformed ref, `GIT` when `cwd` is not a
*   repository or the ref does not exist, `LIMIT_EXCEEDED`, `TIMEOUT`.
*/
async function readFileAtRef(ref, path, cwd, opts = {}) {
	const o = {
		maxBytes: opts.maxBytes ?? 104857600,
		timeoutMs: opts.timeoutMs ?? 3e4
	};
	if (!SAFE_REF.test(ref) || ref.startsWith("-")) throw new DepwardError("INVALID_ARGUMENT", "invalid git ref");
	if (path.includes("\0") || path === "") throw new DepwardError("INVALID_ARGUMENT", "invalid path");
	const commit = await git([
		"rev-parse",
		"--verify",
		"--quiet",
		"--end-of-options",
		`${ref}^{commit}`
	], cwd, o);
	if (!commit.ok) {
		const inRepo = await git(["rev-parse", "--git-dir"], cwd, o);
		throw new DepwardError("GIT", inRepo.ok ? "unknown git ref" : "not inside a git repository");
	}
	const rel = `./${path.replaceAll("\\", "/").replace(/^\.\//, "")}`;
	const blob = await git([
		"cat-file",
		"blob",
		`${commit.stdout.trim()}:${rel}`
	], cwd, o);
	return blob.ok ? blob.stdout : null;
}
/**
* The best common ancestor of `HEAD` and `ref` (`git merge-base HEAD <ref>`), as a full
* commit hash. Comparing against it shows only what the current branch changed, even
* when `ref` has moved on since the branch was created.
*
* @throws DepwardError `INVALID_ARGUMENT` for a malformed ref, `GIT` when `cwd` is not a
*   repository, the ref does not exist, or the two have no common history (for example
*   a shallow clone), `TIMEOUT`.
*/
async function mergeBase(ref, cwd, opts = {}) {
	const o = {
		maxBytes: 1048576,
		timeoutMs: opts.timeoutMs ?? 3e4
	};
	if (!SAFE_REF.test(ref) || ref.startsWith("-")) throw new DepwardError("INVALID_ARGUMENT", "invalid git ref");
	const commit = await git([
		"rev-parse",
		"--verify",
		"--quiet",
		"--end-of-options",
		`${ref}^{commit}`
	], cwd, o);
	if (!commit.ok) {
		const inRepo = await git(["rev-parse", "--git-dir"], cwd, o);
		throw new DepwardError("GIT", inRepo.ok ? `unknown git ref ${ref}` : "not inside a git repository");
	}
	const base = await git([
		"merge-base",
		"HEAD",
		commit.stdout.trim()
	], cwd, o);
	const hash = base.stdout.trim();
	if (!base.ok || !/^[0-9a-f]{40,64}$/.test(hash)) throw new DepwardError("GIT", `HEAD and ${ref} have no common ancestor (in a shallow clone, fetch more history)`);
	return hash;
}
/**
* Which of `paths` (relative to `cwd`) exist as files at git `ref`, in one
* `git ls-tree` call. Cheaper than calling {@link readFileAtRef} for each candidate.
*
* @throws DepwardError `INVALID_ARGUMENT` for a malformed ref or path, `GIT` when `cwd`
*   is not a repository or the ref does not exist, `TIMEOUT`.
*/
async function filesAtRef(ref, paths, cwd, opts = {}) {
	const o = {
		maxBytes: 4194304,
		timeoutMs: opts.timeoutMs ?? 3e4
	};
	if (!SAFE_REF.test(ref) || ref.startsWith("-")) throw new DepwardError("INVALID_ARGUMENT", "invalid git ref");
	const rels = paths.map((p) => {
		if (p.includes("\0") || p === "") throw new DepwardError("INVALID_ARGUMENT", "invalid path");
		return `./${p.replaceAll("\\", "/").replace(/^\.\//, "")}`;
	});
	if (rels.length === 0) return [];
	const commit = await git([
		"rev-parse",
		"--verify",
		"--quiet",
		"--end-of-options",
		`${ref}^{commit}`
	], cwd, o);
	if (!commit.ok) {
		const inRepo = await git(["rev-parse", "--git-dir"], cwd, o);
		throw new DepwardError("GIT", inRepo.ok ? "unknown git ref" : "not inside a git repository");
	}
	const listed = await git([
		"ls-tree",
		"-z",
		"--name-only",
		commit.stdout.trim(),
		"--",
		...rels
	], cwd, o);
	if (!listed.ok) throw new DepwardError("GIT", "git ls-tree failed");
	const present = new Set(listed.stdout.split("\0").filter((s) => s !== ""));
	return paths.filter((p) => present.has(p.replaceAll("\\", "/").replace(/^\.\//, "")));
}
var SAFE_REF;
var init_git = __esmMin((() => {
	init_errors();
	SAFE_REF = /^[\w./~^@{}+-]+$/;
}));
// ../packages/core/src/report/common.ts
/**
* Sorts findings by severity, package, and id (as {@link compareFindings}), breaking ties
* by version, message, and first evidence location, so output never depends on input order.
*/
function sortFindings(findings) {
	return findings.toSorted((a, b) => compareFindings(a, b) || cmp$2(a.version, b.version) || cmp$2(a.message, b.message) || cmp$2(a.evidence[0]?.file, b.evidence[0]?.file) || (a.evidence[0]?.line ?? 0) - (b.evidence[0]?.line ?? 0));
}
/**
* Makes untrusted text safe to print: every unsafe character becomes a visible escape
* (`\x1b`, `‮`), so tampering shows instead of taking effect. Then truncates to `max`
* code points with an ellipsis.
*/
function escapeUnsafe(s, max = 200) {
	const escaped = s.replace(UNSAFE, (c) => {
		const code = c.codePointAt(0) ?? 0;
		return code <= 255 ? `\\x${code.toString(16).padStart(2, "0")}` : hex4(code);
	});
	const chars = [...escaped];
	return chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : escaped;
}
/** `file:line`, `file`, or `undefined`. */
function evidenceLocation(e) {
	if (e.file === void 0) return void 0;
	return e.line !== void 0 && e.line > 0 ? `${e.file}:${e.line}` : e.file;
}
/** `name@version`, or just `name`. */
function packageLabel(f) {
	return f.version ? `${f.package}@${f.version}` : f.package;
}
var cmp$2, UNSAFE_RANGES, hex4, UNSAFE;
var init_common = __esmMin((() => {
	init_findings();
	cmp$2 = (a, b) => (a ?? "") < (b ?? "") ? -1 : (a ?? "") > (b ?? "") ? 1 : 0;
	UNSAFE_RANGES = [
		[0, 31],
		[127, 159],
		[8203, 8207],
		[8232, 8238],
		[8288, 8292],
		[8294, 8297],
		[65279, 65279]
	];
	hex4 = (n) => `\\u${n.toString(16).padStart(4, "0")}`;
	UNSAFE = new RegExp(`[${UNSAFE_RANGES.map(([a, b]) => a === b ? hex4(a) : `${hex4(a)}-${hex4(b)}`).join("")}]`, "gu");
}));
// ../packages/core/src/report/json.ts
var init_json = __esmMin((() => {
	init_common();
}));
// ../packages/core/src/report/markdown.ts
/**
* Escapes untrusted text for Markdown and inline HTML: controls become visible escapes,
* HTML special characters become entities, Markdown punctuation is backslash-escaped,
* newlines become spaces, and `@` gets a zero-width space so it never mentions anyone.
* Truncated to `max` characters (default 200).
*/
function escapeMarkdown(s, max = 200) {
	return escapeUnsafe(s, max).replace(/[\\`*_[\]#|~:]/g, "\\$&").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`).replaceAll("@", "@&#8203;");
}
var init_markdown = __esmMin((() => {
	init_common();
}));
// ../packages/core/src/report/sarif.ts
/**
* Renders a SARIF 2.1.0 log with one run. Rules are the distinct finding IDs; a rule's
* default level and security severity come from its most severe finding. Each result
* has a stable `primaryLocationLineHash` derived from (id, package, version), so
* re-uploads update alerts instead of duplicating them.
*/
function renderSarif(findings, opts = {}) {
	const sorted = sortFindings(findings);
	const locate = opts.locate ?? (() => ({
		uri: "package.json",
		line: 1
	}));
	const firstById = /* @__PURE__ */ new Map();
	for (const f of sorted) if (!firstById.has(f.id)) firstById.set(f.id, f);
	const ids = [...firstById.keys()].toSorted();
	const index = new Map(ids.map((id, i) => [id, i]));
	const rules = ids.map((id) => {
		const f = firstById.get(id);
		const description = cap$1(nonEmpty(f.message, id), 1024);
		const properties = {
			tags: ["security", "supply-chain"],
			precision: "medium"
		};
		const sev = SECURITY_SEVERITY[f.severity];
		if (sev !== void 0) properties["security-severity"] = sev;
		return {
			id,
			name: cap$1(id, 255),
			shortDescription: { text: description },
			fullDescription: { text: safeUrl(f.docsUrl) ? cap$1(`${description}. See ${f.docsUrl}`, 1024) : description },
			help: safeUrl(f.docsUrl) ? {
				text: `See ${f.docsUrl}`,
				markdown: `See the [finding catalog](${f.docsUrl}).`
			} : { text: `Finding ${id}; see the depward finding catalog.` },
			...safeUrl(f.docsUrl) ? { helpUri: f.docsUrl } : {},
			defaultConfiguration: { level: LEVEL[f.severity] },
			properties
		};
	});
	const seen = /* @__PURE__ */ new Map();
	const results = sorted.map((f) => {
		const loc = locate(f);
		const key = `${f.id}\0${f.package}\0${f.version ?? ""}`;
		const n = seen.get(key) ?? 0;
		seen.set(key, n + 1);
		const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);
		const properties = {
			severity: f.severity,
			package: f.package
		};
		if (f.version !== void 0) properties["version"] = f.version;
		return {
			ruleId: f.id,
			ruleIndex: index.get(f.id) ?? 0,
			level: LEVEL[f.severity],
			message: { text: messageText(f) },
			locations: [{ physicalLocation: {
				artifactLocation: { uri: nonEmpty(loc.uri, "package.json") },
				region: { startLine: Math.max(1, Math.trunc(loc.line ?? 1)) }
			} }],
			partialFingerprints: { primaryLocationLineHash: `${hash}:${n + 1}` },
			properties
		};
	});
	const driver = {
		name: opts.tool?.name ?? "depward",
		informationUri: INFO_URI
	};
	if (opts.tool?.version !== void 0) {
		driver["version"] = opts.tool.version;
		driver["semanticVersion"] = opts.tool.version;
	}
	driver["rules"] = rules;
	return `${JSON.stringify({
		$schema: SCHEMA,
		version: "2.1.0",
		runs: [{
			tool: { driver },
			results
		}]
	}, null, 2)}\n`;
}
/** Plain-text message: the first sentence names the package; evidence follows. */
function messageText(f) {
	const lines = [cap$1(`${packageLabel(f)}: ${nonEmpty(f.message, f.id)}.`, 500)];
	for (const e of f.evidence.slice(0, 20)) {
		const loc = evidenceLocation(e);
		const text = [
			loc === void 0 ? void 0 : cap$1(loc, 200),
			e.snippet === void 0 ? void 0 : `"${cap$1(e.snippet, 200)}"`,
			e.detail === void 0 ? void 0 : cap$1(e.detail, 200)
		].filter((p) => p !== void 0).join(" ");
		if (text) lines.push(`- ${text}`);
	}
	return lines.join("\n");
}
var LEVEL, SECURITY_SEVERITY, SCHEMA, INFO_URI, cap$1, safeUrl, nonEmpty;
var init_sarif = __esmMin((() => {
	init_common();
	LEVEL = {
		critical: "error",
		high: "error",
		medium: "warning",
		low: "note",
		info: "note"
	};
	SECURITY_SEVERITY = {
		critical: "9.5",
		high: "8.0",
		medium: "5.5",
		low: "3.0",
		info: void 0
	};
	SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
	INFO_URI = "https://github.com/lavitsamson/depward";
	cap$1 = (s, max) => escapeUnsafe(s, max);
	safeUrl = (u) => /^https:\/\/[^\s<>"'()]+$/.test(u);
	nonEmpty = (s, fallback) => s.trim() === "" ? fallback : s;
}));
// ../packages/core/src/report/terminal.ts
var init_terminal = __esmMin((() => {
	init_common();
}));
// ../packages/core/src/report/index.ts
var init_report = __esmMin((() => {
	init_common();
	init_json();
	init_markdown();
	init_sarif();
	init_terminal();
}));
// ../packages/core/src/index.ts
var init_src$1 = __esmMin((() => {
	init_errors();
	init_findings();
	init_secret();
	init_config();
	init_cache();
	init_integrity();
	init_client();
	init_npmrc();
	init_types$2();
	init_resolve();
	init_history();
	init_tar();
	init_lockfile();
	init_git();
	init_report();
}));
// ../packages/analyzer/src/classify.ts
/** Classifies one package file. */
function classifyFile(path, data) {
	const format = binaryFormat(data);
	if (format === "wasm" || /\.wasm$/i.test(path)) return {
		kind: "wasm",
		format: "wasm"
	};
	if (format) return {
		kind: "native",
		format
	};
	if (/\.node$/i.test(path)) return {
		kind: "native",
		format: "node addon"
	};
	if (JS_EXT.test(path)) return { kind: "js" };
	if (/\.json$/i.test(path)) return { kind: "json" };
	if (DECLARATION.test(path)) return { kind: "other" };
	if (SOURCE_EXT.test(path)) return { kind: "source" };
	if (!/\.[^/]*$/.test(basename$1(path)) && hasNodeShebang(data)) return { kind: "js" };
	return { kind: "other" };
}
function basename$1(path) {
	return path.slice(path.lastIndexOf("/") + 1);
}
function hasNodeShebang(data) {
	if (data[0] !== 35 || data[1] !== 33) return false;
	const end = data.indexOf(10);
	const line = new TextDecoder().decode(data.subarray(0, end < 0 ? Math.min(data.length, 200) : Math.min(end, 200)));
	return /\bnode\b/.test(line);
}
/** Detects ELF, Mach-O (thin and fat), PE, and wasm by magic bytes. */
function binaryFormat(d) {
	if (d.length < 8) return void 0;
	const be = u32be(d, 0);
	if (be === 2135247942) return "ELF";
	if (be === 6386541) return "wasm";
	if (be === 4277009102 || be === 4277009103 || be === 3472551422 || be === 3489328638) return "Mach-O";
	if (be === 3405691582 && u32be(d, 4) > 0 && u32be(d, 4) < 20) return "Mach-O";
	if (d[0] === 77 && d[1] === 90 && d.length >= 64) {
		const peOffset = u32le(d, 60);
		if (peOffset + 4 <= d.length && u32be(d, peOffset) === 1346699264) return "PE";
	}
}
/** Heuristic: a `.min.js` name, or code whose lines are very long on average. */
function looksMinified(path, text) {
	if (/\.min\.[cm]?js$/i.test(path)) return true;
	if (text.length < 512) return false;
	let lines = 1;
	for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) lines++;
	return text.length / lines > 250 || lines <= 3 && text.length > 2e3;
}
/** Heuristic: contains a well-known bundler runtime marker. */
function looksBundled(text) {
	return BUNDLE_MARKERS.some((m) => text.includes(m));
}
var JS_EXT, SOURCE_EXT, DECLARATION, u32be, u32le, BUNDLE_MARKERS;
var init_classify = __esmMin((() => {
	JS_EXT = /\.(?:js|cjs|mjs)$/i;
	SOURCE_EXT = /\.(?:ts|mts|cts|tsx|jsx)$/i;
	DECLARATION = /\.d\.(?:ts|mts|cts)$/i;
	u32be = (d, o) => ((d[o] ?? 0) << 24 | (d[o + 1] ?? 0) << 16 | (d[o + 2] ?? 0) << 8 | (d[o + 3] ?? 0)) >>> 0;
	u32le = (d, o) => ((d[o] ?? 0) | (d[o + 1] ?? 0) << 8 | (d[o + 2] ?? 0) << 16 | (d[o + 3] ?? 0) << 24) >>> 0;
	BUNDLE_MARKERS = [
		"__webpack_require__",
		"__webpack_modules__",
		"__commonJS(",
		"__toESM(",
		"parcelRequire",
		"function r(e,n,t){function o(i,f){if(!n[i])"
	];
}));
// ../node_modules/.pnpm/acorn@8.19.0/node_modules/acorn/dist/acorn.mjs
function isInAstralSet(code, set) {
	var pos = 65536;
	for (var i = 0; i < set.length; i += 2) {
		pos += set[i];
		if (pos > code) return false;
		pos += set[i + 1];
		if (pos >= code) return true;
	}
	return false;
}
function isIdentifierStart(code, astral) {
	if (code < 65) return code === 36;
	if (code < 91) return true;
	if (code < 97) return code === 95;
	if (code < 123) return true;
	if (code <= 65535) return code >= 170 && nonASCIIidentifierStart.test(String.fromCharCode(code));
	if (astral === false) return false;
	return isInAstralSet(code, astralIdentifierStartCodes);
}
function isIdentifierChar(code, astral) {
	if (code < 48) return code === 36;
	if (code < 58) return true;
	if (code < 65) return false;
	if (code < 91) return true;
	if (code < 97) return code === 95;
	if (code < 123) return true;
	if (code <= 65535) return code >= 170 && nonASCIIidentifier.test(String.fromCharCode(code));
	if (astral === false) return false;
	return isInAstralSet(code, astralIdentifierStartCodes) || isInAstralSet(code, astralIdentifierCodes);
}
function binop(name, prec) {
	return new TokenType(name, {
		beforeExpr: true,
		binop: prec
	});
}
function kw(name, options) {
	if (options === void 0) options = {};
	options.keyword = name;
	return keywords[name] = new TokenType(name, options);
}
function isNewLine(code) {
	return code === 10 || code === 13 || code === 8232 || code === 8233;
}
function nextLineBreak(code, from, end) {
	if (end === void 0) end = code.length;
	for (var i = from; i < end; i++) {
		var next = code.charCodeAt(i);
		if (isNewLine(next)) return i < end - 1 && next === 13 && code.charCodeAt(i + 1) === 10 ? i + 2 : i + 1;
	}
	return -1;
}
function wordsRegexp(words) {
	return regexpCache[words] || (regexpCache[words] = new RegExp("^(?:" + words.replace(/ /g, "|") + ")$"));
}
function codePointToString(code) {
	if (code <= 65535) return String.fromCharCode(code);
	code -= 65536;
	return String.fromCharCode((code >> 10) + 55296, (code & 1023) + 56320);
}
function getLineInfo(input, offset) {
	for (var line = 1, cur = 0;;) {
		var nextBreak = nextLineBreak(input, cur, offset);
		if (nextBreak < 0) return new Position(line, offset - cur);
		++line;
		cur = nextBreak;
	}
}
function getOptions(opts) {
	var options = {};
	for (var opt in defaultOptions) options[opt] = opts && hasOwn(opts, opt) ? opts[opt] : defaultOptions[opt];
	if (options.ecmaVersion === "latest") options.ecmaVersion = 1e8;
	else if (options.ecmaVersion == null) {
		if (!warnedAboutEcmaVersion && typeof console === "object" && console.warn) {
			warnedAboutEcmaVersion = true;
			console.warn("Since Acorn 8.0.0, options.ecmaVersion is required.\nDefaulting to 2020, but this will stop working in the future.");
		}
		options.ecmaVersion = 11;
	} else if (options.ecmaVersion >= 2015) options.ecmaVersion -= 2009;
	if (options.allowReserved == null) options.allowReserved = options.ecmaVersion < 5;
	if (!opts || opts.allowHashBang == null) options.allowHashBang = options.ecmaVersion >= 14;
	if (isArray(options.onToken)) {
		var tokens = options.onToken;
		options.onToken = function(token) {
			return tokens.push(token);
		};
	}
	if (isArray(options.onComment)) options.onComment = pushComment(options, options.onComment);
	if (options.sourceType === "commonjs" && options.allowAwaitOutsideFunction) throw new Error("Cannot use allowAwaitOutsideFunction with sourceType: commonjs");
	return options;
}
function pushComment(options, array) {
	return function(block, text, start, end, startLoc, endLoc) {
		var comment = {
			type: block ? "Block" : "Line",
			value: text,
			start,
			end
		};
		if (options.locations) comment.loc = new SourceLocation(this, startLoc, endLoc);
		if (options.ranges) comment.range = [start, end];
		array.push(comment);
	};
}
function functionFlags(async, generator) {
	return SCOPE_FUNCTION | (async ? SCOPE_ASYNC : 0) | (generator ? SCOPE_GENERATOR : 0);
}
function keywordOpAt(parser, pos) {
	var end = pos + 1, stop = Math.min(parser.input.length, pos + 11);
	while (end < stop) {
		var ch = parser.fullCharCodeAt(end);
		if (!isIdentifierChar(ch, true)) break;
		end += ch <= 65535 ? 1 : 2;
	}
	return end === pos + 2 && parser.input.slice(pos, end) === "in" || end === pos + 10 && parser.input.slice(pos, end) === "instanceof";
}
function isPrivateNameConflicted(privateNameMap, element) {
	var name = element.key.name;
	var curr = privateNameMap[name];
	var next = "true";
	if (element.type === "MethodDefinition" && (element.kind === "get" || element.kind === "set")) next = (element.static ? "s" : "i") + element.kind;
	if (curr === "iget" && next === "iset" || curr === "iset" && next === "iget" || curr === "sget" && next === "sset" || curr === "sset" && next === "sget") {
		privateNameMap[name] = "true";
		return false;
	} else if (!curr) {
		privateNameMap[name] = next;
		return false;
	} else return true;
}
function checkKeyName(node, name) {
	var computed = node.computed;
	var key = node.key;
	return !computed && (key.type === "Identifier" && key.name === name || key.type === "Literal" && key.value === name);
}
function isLocalVariableAccess(node) {
	return node.type === "Identifier" || node.type === "ParenthesizedExpression" && isLocalVariableAccess(node.expression);
}
function isPrivateFieldAccess(node) {
	return node.type === "MemberExpression" && node.property.type === "PrivateIdentifier" || node.type === "ChainExpression" && isPrivateFieldAccess(node.expression) || node.type === "ParenthesizedExpression" && isPrivateFieldAccess(node.expression);
}
function finishNodeAt(node, type, pos, loc) {
	node.type = type;
	node.end = pos;
	if (this.options.locations) node.loc.end = loc;
	if (this.options.ranges) node.range[1] = pos;
	return node;
}
function buildUnicodeData(ecmaVersion) {
	var d = data[ecmaVersion] = {
		binary: wordsRegexp(unicodeBinaryProperties[ecmaVersion] + " " + unicodeGeneralCategoryValues),
		binaryOfStrings: wordsRegexp(unicodeBinaryPropertiesOfStrings[ecmaVersion]),
		nonBinary: {
			General_Category: wordsRegexp(unicodeGeneralCategoryValues),
			Script: wordsRegexp(unicodeScriptValues[ecmaVersion])
		}
	};
	d.nonBinary.Script_Extensions = d.nonBinary.Script;
	d.nonBinary.gc = d.nonBinary.General_Category;
	d.nonBinary.sc = d.nonBinary.Script;
	d.nonBinary.scx = d.nonBinary.Script_Extensions;
}
function hasProp(obj) {
	for (var _ in obj) return true;
	return false;
}
function isRegularExpressionModifier(ch) {
	return ch === 105 || ch === 109 || ch === 115;
}
function isSyntaxCharacter(ch) {
	return ch === 36 || ch >= 40 && ch <= 43 || ch === 46 || ch === 63 || ch >= 91 && ch <= 94 || ch >= 123 && ch <= 125;
}
function isRegExpIdentifierStart(ch) {
	return isIdentifierStart(ch, true) || ch === 36 || ch === 95;
}
function isRegExpIdentifierPart(ch) {
	return isIdentifierChar(ch, true) || ch === 36 || ch === 95 || ch === 8204 || ch === 8205;
}
function isControlLetter(ch) {
	return ch >= 65 && ch <= 90 || ch >= 97 && ch <= 122;
}
function isValidUnicode(ch) {
	return ch >= 0 && ch <= 1114111;
}
function isCharacterClassEscape(ch) {
	return ch === 100 || ch === 68 || ch === 115 || ch === 83 || ch === 119 || ch === 87;
}
function isUnicodePropertyNameCharacter(ch) {
	return isControlLetter(ch) || ch === 95;
}
function isUnicodePropertyValueCharacter(ch) {
	return isUnicodePropertyNameCharacter(ch) || isDecimalDigit(ch);
}
function isClassSetReservedDoublePunctuatorCharacter(ch) {
	return ch === 33 || ch >= 35 && ch <= 38 || ch >= 42 && ch <= 44 || ch === 46 || ch >= 58 && ch <= 64 || ch === 94 || ch === 96 || ch === 126;
}
function isClassSetSyntaxCharacter(ch) {
	return ch === 40 || ch === 41 || ch === 45 || ch === 47 || ch >= 91 && ch <= 93 || ch >= 123 && ch <= 125;
}
function isClassSetReservedPunctuator(ch) {
	return ch === 33 || ch === 35 || ch === 37 || ch === 38 || ch === 44 || ch === 45 || ch >= 58 && ch <= 62 || ch === 64 || ch === 96 || ch === 126;
}
function isDecimalDigit(ch) {
	return ch >= 48 && ch <= 57;
}
function isHexDigit(ch) {
	return ch >= 48 && ch <= 57 || ch >= 65 && ch <= 70 || ch >= 97 && ch <= 102;
}
function hexToInt(ch) {
	if (ch >= 65 && ch <= 70) return 10 + (ch - 65);
	if (ch >= 97 && ch <= 102) return 10 + (ch - 97);
	return ch - 48;
}
function isOctalDigit(ch) {
	return ch >= 48 && ch <= 55;
}
function stringToNumber(str, isLegacyOctalNumericLiteral) {
	if (isLegacyOctalNumericLiteral) return parseInt(str, 8);
	return parseFloat(str.replace(/_/g, ""));
}
function stringToBigInt(str) {
	if (typeof BigInt !== "function") return null;
	return BigInt(str.replace(/_/g, ""));
}
function parse(input, options) {
	return Parser.parse(input, options);
}
var astralIdentifierCodes, astralIdentifierStartCodes, nonASCIIidentifierChars, nonASCIIidentifierStartChars, reservedWords, ecma5AndLessKeywords, keywords$1, keywordRelationalOperator, nonASCIIidentifierStart, nonASCIIidentifier, TokenType, beforeExpr, startsExpr, keywords, types$1, lineBreak, lineBreakG, nonASCIIwhitespace, skipWhiteSpace, ref, hasOwnProperty, toString, hasOwn, isArray, regexpCache, loneSurrogate, Position, SourceLocation, defaultOptions, warnedAboutEcmaVersion, SCOPE_TOP, SCOPE_FUNCTION, SCOPE_ASYNC, SCOPE_GENERATOR, SCOPE_ARROW, SCOPE_SIMPLE_CATCH, SCOPE_SUPER, SCOPE_DIRECT_SUPER, SCOPE_CLASS_STATIC_BLOCK, SCOPE_CLASS_FIELD_INIT, SCOPE_SWITCH, SCOPE_VAR, BIND_NONE, BIND_VAR, BIND_LEXICAL, BIND_FUNCTION, BIND_SIMPLE_CATCH, BIND_OUTSIDE, Parser, prototypeAccessors, pp$9, literal, DestructuringErrors, pp$8, loopLabel, switchLabel, empty$1, FUNC_STATEMENT, FUNC_HANGING_STATEMENT, FUNC_NULLABLE_ID, pp$7, TokContext, types, pp$6, pp$5, empty$2, pp$4, pp$3, Scope, Node, pp$2, scriptValuesAddedInUnicode, ecma9BinaryProperties, ecma10BinaryProperties, ecma11BinaryProperties, ecma12BinaryProperties, ecma13BinaryProperties, unicodeBinaryProperties, unicodeBinaryPropertiesOfStrings, unicodeGeneralCategoryValues, ecma9ScriptValues, ecma10ScriptValues, ecma11ScriptValues, ecma12ScriptValues, ecma13ScriptValues, unicodeScriptValues, data, i, list, ecmaVersion, pp$1, BranchID, RegExpValidationState, CharSetNone, CharSetOk, CharSetString, Token, pp, INVALID_TEMPLATE_ESCAPE_ERROR, version;
var init_acorn = __esmMin((() => {
	astralIdentifierCodes = [
		509,
		0,
		227,
		0,
		150,
		4,
		294,
		9,
		1368,
		2,
		2,
		1,
		6,
		3,
		41,
		2,
		5,
		0,
		166,
		1,
		574,
		3,
		9,
		9,
		7,
		9,
		32,
		4,
		318,
		1,
		31,
		4,
		33,
		15,
		71,
		10,
		50,
		3,
		123,
		2,
		54,
		14,
		32,
		10,
		3,
		1,
		11,
		3,
		46,
		10,
		8,
		0,
		46,
		9,
		7,
		2,
		37,
		13,
		2,
		9,
		6,
		1,
		45,
		0,
		13,
		2,
		49,
		13,
		9,
		3,
		2,
		11,
		83,
		11,
		7,
		0,
		3,
		0,
		158,
		11,
		6,
		9,
		7,
		3,
		56,
		1,
		2,
		6,
		3,
		1,
		3,
		2,
		10,
		0,
		11,
		1,
		3,
		6,
		4,
		4,
		68,
		8,
		2,
		0,
		3,
		0,
		2,
		3,
		2,
		4,
		2,
		0,
		15,
		1,
		83,
		17,
		10,
		9,
		5,
		0,
		82,
		19,
		13,
		9,
		214,
		6,
		3,
		8,
		28,
		1,
		83,
		16,
		16,
		9,
		82,
		12,
		9,
		9,
		7,
		19,
		58,
		14,
		5,
		9,
		243,
		14,
		166,
		9,
		71,
		5,
		2,
		1,
		3,
		3,
		2,
		0,
		2,
		1,
		13,
		9,
		120,
		6,
		3,
		6,
		4,
		0,
		29,
		9,
		41,
		6,
		2,
		3,
		9,
		0,
		10,
		10,
		47,
		15,
		199,
		7,
		137,
		9,
		54,
		7,
		2,
		7,
		17,
		9,
		57,
		21,
		2,
		13,
		123,
		5,
		4,
		0,
		2,
		1,
		2,
		6,
		2,
		0,
		9,
		9,
		49,
		4,
		2,
		1,
		2,
		4,
		9,
		9,
		55,
		9,
		7,
		0,
		259,
		3,
		10,
		1,
		2,
		0,
		49,
		6,
		4,
		4,
		14,
		10,
		5350,
		0,
		7,
		14,
		11465,
		27,
		2343,
		9,
		87,
		9,
		39,
		4,
		60,
		6,
		26,
		9,
		535,
		9,
		470,
		0,
		2,
		54,
		8,
		3,
		82,
		0,
		12,
		1,
		19628,
		1,
		4178,
		9,
		519,
		45,
		3,
		22,
		481,
		1,
		61,
		4,
		4,
		5,
		9,
		7,
		3,
		6,
		31,
		3,
		149,
		2,
		12,
		2,
		9,
		1,
		3,
		0,
		33,
		1,
		1357,
		49,
		513,
		54,
		5,
		49,
		9,
		0,
		15,
		0,
		23,
		4,
		2,
		14,
		1361,
		6,
		2,
		16,
		3,
		6,
		2,
		1,
		2,
		4,
		101,
		0,
		161,
		6,
		10,
		9,
		357,
		0,
		62,
		13,
		499,
		13,
		245,
		1,
		2,
		9,
		233,
		0,
		3,
		0,
		8,
		1,
		6,
		0,
		475,
		6,
		110,
		6,
		6,
		9,
		4759,
		9,
		787719,
		239
	];
	astralIdentifierStartCodes = [
		0,
		11,
		2,
		25,
		2,
		18,
		2,
		1,
		2,
		14,
		3,
		13,
		35,
		122,
		70,
		52,
		268,
		28,
		4,
		48,
		48,
		31,
		14,
		29,
		6,
		37,
		11,
		29,
		3,
		35,
		5,
		7,
		2,
		4,
		43,
		157,
		19,
		35,
		5,
		35,
		5,
		39,
		9,
		51,
		13,
		10,
		2,
		14,
		2,
		6,
		2,
		1,
		2,
		10,
		2,
		14,
		2,
		6,
		2,
		1,
		4,
		51,
		13,
		310,
		10,
		21,
		11,
		7,
		25,
		5,
		2,
		41,
		2,
		13,
		65,
		5,
		3,
		0,
		2,
		43,
		2,
		1,
		4,
		0,
		3,
		22,
		11,
		22,
		10,
		30,
		66,
		18,
		2,
		1,
		11,
		21,
		11,
		25,
		7,
		25,
		39,
		55,
		7,
		1,
		65,
		0,
		16,
		3,
		2,
		2,
		2,
		28,
		43,
		28,
		4,
		28,
		36,
		7,
		2,
		27,
		28,
		53,
		11,
		21,
		11,
		18,
		14,
		17,
		111,
		72,
		56,
		50,
		14,
		50,
		14,
		35,
		39,
		27,
		10,
		22,
		251,
		41,
		7,
		1,
		17,
		5,
		18,
		21,
		18,
		28,
		11,
		0,
		9,
		21,
		43,
		17,
		47,
		20,
		28,
		22,
		13,
		52,
		58,
		1,
		3,
		0,
		14,
		44,
		33,
		24,
		27,
		35,
		30,
		0,
		3,
		0,
		9,
		34,
		4,
		0,
		13,
		47,
		15,
		3,
		22,
		0,
		2,
		0,
		36,
		17,
		2,
		24,
		20,
		1,
		64,
		6,
		2,
		0,
		2,
		3,
		2,
		14,
		2,
		9,
		8,
		46,
		39,
		7,
		3,
		1,
		3,
		21,
		2,
		6,
		2,
		1,
		2,
		4,
		4,
		0,
		19,
		0,
		13,
		4,
		31,
		9,
		2,
		0,
		3,
		0,
		2,
		37,
		2,
		0,
		26,
		0,
		2,
		0,
		45,
		52,
		19,
		3,
		21,
		2,
		31,
		47,
		21,
		1,
		2,
		0,
		185,
		46,
		42,
		3,
		37,
		47,
		21,
		0,
		60,
		42,
		14,
		0,
		72,
		26,
		38,
		6,
		186,
		43,
		117,
		63,
		32,
		7,
		3,
		0,
		3,
		7,
		2,
		1,
		2,
		23,
		16,
		0,
		2,
		0,
		95,
		7,
		3,
		38,
		17,
		0,
		2,
		0,
		29,
		0,
		11,
		39,
		8,
		0,
		22,
		0,
		12,
		45,
		20,
		0,
		19,
		72,
		18,
		0,
		182,
		32,
		32,
		8,
		2,
		36,
		18,
		0,
		50,
		29,
		113,
		6,
		2,
		1,
		2,
		37,
		22,
		0,
		26,
		5,
		2,
		1,
		2,
		31,
		15,
		0,
		24,
		43,
		22,
		0,
		239,
		18,
		16,
		0,
		2,
		12,
		2,
		33,
		125,
		0,
		80,
		921,
		103,
		111,
		6,
		206,
		13,
		310,
		2314,
		96,
		16,
		1071,
		18,
		5,
		26,
		3994,
		6,
		582,
		6842,
		29,
		1763,
		568,
		8,
		30,
		18,
		78,
		18,
		29,
		19,
		47,
		17,
		3,
		32,
		20,
		6,
		18,
		433,
		44,
		212,
		63,
		33,
		24,
		3,
		24,
		45,
		74,
		6,
		0,
		67,
		12,
		65,
		1,
		2,
		0,
		15,
		4,
		10,
		7386,
		37,
		33,
		96,
		114,
		14,
		913,
		15,
		50,
		7710,
		3,
		2,
		6,
		2,
		1,
		2,
		296,
		10,
		0,
		30,
		2,
		3,
		0,
		15,
		4,
		8,
		395,
		2309,
		106,
		6,
		12,
		4,
		8,
		8,
		9,
		5991,
		84,
		2,
		70,
		2,
		1,
		3,
		0,
		3,
		1,
		3,
		3,
		2,
		11,
		2,
		0,
		2,
		6,
		2,
		64,
		2,
		3,
		3,
		7,
		2,
		6,
		2,
		27,
		2,
		3,
		2,
		4,
		2,
		0,
		4,
		6,
		2,
		340,
		2,
		24,
		2,
		24,
		2,
		30,
		2,
		24,
		2,
		30,
		2,
		24,
		2,
		30,
		2,
		24,
		2,
		30,
		2,
		24,
		2,
		7,
		1845,
		129,
		15,
		6,
		55,
		50,
		49,
		61,
		147,
		44,
		11,
		6,
		17,
		0,
		322,
		29,
		19,
		43,
		485,
		27,
		229,
		29,
		3,
		0,
		208,
		30,
		2,
		2,
		2,
		1,
		2,
		6,
		3,
		4,
		10,
		1,
		225,
		6,
		2,
		3,
		2,
		1,
		2,
		14,
		2,
		196,
		60,
		67,
		8,
		0,
		1205,
		3,
		2,
		26,
		2,
		1,
		2,
		0,
		3,
		0,
		2,
		9,
		2,
		3,
		2,
		0,
		2,
		0,
		7,
		0,
		5,
		0,
		2,
		0,
		2,
		0,
		2,
		2,
		2,
		1,
		2,
		0,
		3,
		0,
		2,
		0,
		2,
		0,
		2,
		0,
		2,
		0,
		2,
		1,
		2,
		0,
		3,
		3,
		2,
		6,
		2,
		3,
		2,
		3,
		2,
		0,
		2,
		9,
		2,
		16,
		6,
		2,
		2,
		4,
		2,
		16,
		4421,
		42719,
		33,
		4382,
		2,
		5773,
		3,
		7472,
		16,
		621,
		2467,
		541,
		1507,
		4938,
		6,
		8489,
		39815,
		11327
	];
	nonASCIIidentifierChars = "‌‍·̀-ͯ·҃-֑҇-ׇֽֿׁׂׅׄ-׉ؐ-ًؚ-٩ٰۖ-ۜ۟-۪ۤۧۨ-ۭ۰-۹ܑܰ-݊ަ-ް߀-߉߫-߽߳ࠖ-࠙ࠛ-ࠣࠥ-ࠧࠩ-࡙࠭-࡛ࢗ-࢟࣊-ࣣ࣡-ःऺ-़ा-ॏ॑-ॗॢॣ०-९ঁ-ঃ়া-ৄেৈো-্ৗৢৣ০-৯৾ਁ-ਃ਼ਾ-ੂੇੈੋ-੍ੑ੦-ੱੵઁ-ઃ઼ા-ૅે-ૉો-્ૢૣ૦-૯ૺ-૿ଁ-ଃ଼ା-ୄେୈୋ-୍୓-ୗୢୣ୦-୯ஂா-ூெ-ைொ-்ௗ௦-௯ఀ-ఄ఼ా-ౄె-ైొ-్ౕౖౢౣ౦-౯ಁ-ಃ಼ಾ-ೄೆ-ೈೊ-್ೕೖೢೣ೦-೯ೳഀ-ഃ഻഼ാ-ൄെ-ൈൊ-്ൗൢൣ൦-൯ඁ-ඃ්ා-ුූෘ-ෟ෦-෯ෲෳัิ-ฺ็-๎๐-๙ັິ-ຼ່-໎໐-໙༘༙༠-༩༹༵༷༾༿ཱ-྄྆྇ྍ-ྗྙ-ྼ࿆ါ-ှ၀-၉ၖ-ၙၞ-ၠၢ-ၤၧ-ၭၱ-ၴႂ-ႍႏ-ႝ፝-፟፩-፱ᜒ-᜕ᜲ-᜴ᝒᝓᝲᝳ឴-៓៝០-៩᠋-᠍᠏-᠙ᢩᤠ-ᤫᤰ-᤻᥆-᥏᧐-᧚ᨗ-ᨛᩕ-ᩞ᩠-᩿᩼-᪉᪐-᪙᪰-᪽ᪿ-᫰ᬀ-ᬄ᬴-᭄᭐-᭙᭫-᭳ᮀ-ᮂᮡ-ᮭ᮰-᮹᯦-᯳ᰤ-᰷᱀-᱉᱐-᱙᳐-᳔᳒-᳨᳭᳴᳷-᳹᷀-᷿‌‍‿⁀⁔⃐-⃥⃜⃡-⃰⳯-⵿⳱ⷠ-〪ⷿ-゙゚〯・꘠-꘩꙯ꙴ-꙽ꚞꚟ꛰꛱ꠂ꠆ꠋꠣ-ꠧ꠬ꢀꢁꢴ-ꣅ꣐-꣙꣠-꣱ꣿ-꤉ꤦ-꤭ꥇ-꥓ꦀ-ꦃ꦳-꧀꧐-꧙ꧥ꧰-꧹ꨩ-ꨶꩃꩌꩍ꩐-꩙ꩻ-ꩽꪰꪲ-ꪴꪷꪸꪾ꪿꫁ꫫ-ꫯꫵ꫶ꯣ-ꯪ꯬꯭꯰-꯹ﬞ︀-️︠-︯︳︴﹍-﹏０-９＿･";
	nonASCIIidentifierStartChars = "ªµºÀ-ÖØ-öø-ˁˆ-ˑˠ-ˤˬˮͰ-ʹͶͷͺ-ͽͿΆΈ-ΊΌΎ-ΡΣ-ϵϷ-ҁҊ-ԯԱ-Ֆ՘ՙՠ-ֈ֋֌א-תׯ-ײؠ-يٮٯٱ-ۓەۥۦۮۯۺ-ۼۿܐܒ-ܯݍ-ޥޱߊ-ߪߴߵߺࠀ-ࠕࠚࠤࠨࡀ-ࡘࡠ-ࡪࡰ-ࢇࢉ-࢏ࢠ-ࣉऄ-हऽॐक़-ॡॱ-ঀঅ-ঌএঐও-নপ-রলশ-হঽৎড়ঢ়য়-ৡৰৱৼਅ-ਊਏਐਓ-ਨਪ-ਰਲਲ਼ਵਸ਼ਸਹਖ਼-ੜਫ਼ੲ-ੴઅ-ઍએ-ઑઓ-નપ-રલળવ-હઽૐૠૡૹଅ-ଌଏଐଓ-ନପ-ରଲଳଵ-ହଽଡ଼ଢ଼ୟ-ୡୱஃஅ-ஊஎ-ஐஒ-கஙசஜஞடணதந-பம-ஹௐఅ-ఌఎ-ఐఒ-నప-హఽౘ-ౚ౜ౝౠౡಀಅ-ಌಎ-ಐಒ-ನಪ-ಳವ-ಹಽ೜-ೞೠೡೱೲഄ-ഌഎ-ഐഒ-ഺഽൎൔ-ൖൟ-ൡൺ-ൿඅ-ඖක-නඳ-රලව-ෆก-ะาำเ-ๆກຂຄຆ-ຊຌ-ຣລວ-ະາຳຽເ-ໄໆໜ-ໟༀཀ-ཇཉ-ཬྈ-ྌက-ဪဿၐ-ၕၚ-ၝၡၥၦၮ-ၰၵ-ႁႎႠ-ჅჇჍა-ჺჼ-ቈቊ-ቍቐ-ቖቘቚ-ቝበ-ኈኊ-ኍነ-ኰኲ-ኵኸ-ኾዀዂ-ዅወ-ዖዘ-ጐጒ-ጕጘ-ፚᎀ-ᎏᎠ-Ᏽᏸ-ᏽᐁ-ᙬᙯ-ᙿᚁ-ᚚᚠ-ᛪᛮ-ᛸᜀ-ᜑᜟ-ᜱᝀ-ᝑᝠ-ᝬᝮ-ᝰក-ឳៗៜᠠ-ᡸᢀ-ᢨᢪᢰ-ᣵᤀ-ᤞᥐ-ᥭᥰ-ᥴᦀ-ᦫᦰ-ᧉᨀ-ᨖᨠ-ᩔᪧᬅ-ᬳᭅ-ᭌᮃ-ᮠᮮᮯᮺ-ᯥᰀ-ᰣᱍ-ᱏᱚ-ᱽᲀ-ᲊᲐ-ᲺᲽ-Ჿᳩ-ᳬᳮ-ᳳᳵᳶᳺᴀ-ᶿḀ-ἕἘ-Ἕἠ-ὅὈ-Ὅὐ-ὗὙὛὝὟ-ώᾀ-ᾴᾶ-ᾼιῂ-ῄῆ-ῌῐ-ΐῖ-Ίῠ-Ῥῲ-ῴῶ-ῼⁱⁿ₏-₟ℂℇℊ-ℓℕ℘-ℝℤΩℨK-ℹℼ-ℿⅅ-ⅉⅎⅠ-ↈⰀ-ⳤⳫ-ⳮⳲⳳⴀ-ⴥⴧⴭⴰ-ⵧⵯⶀ-ⶖⶠ-ⶦⶨ-ⶮⶰ-ⶶⶸ-ⶾⷀ-ⷆⷈ-ⷎⷐ-ⷖⷘ-ⷞ々-〇〡-〩〱-〵〸-〼ぁ-ゖ゛-ゟァ-ヺー-ヿㄅ-ㄯㄱ-ㆎㆠ-ㆿㇰ-ㇿ㐀-䶿一-ꒌꓐ-ꓽꔀ-ꘌꘐ-ꘟꘪꘫꙀ-ꙮꙿ-ꚝꚠ-ꛯꜗ-ꜟꜢ-ꞈꞋ-꟝꟢꟱-ꠁꠃ-ꠅꠇ-ꠊꠌ-ꠢꡀ-ꡳꢂ-ꢳꣲ-ꣷꣻꣽꣾꤊ-ꤥꤰ-ꥆꥠ-ꥼꦄ-ꦲꧏꧠ-ꧤꧦ-ꧯꧺ-ꧾꨀ-ꨨꩀ-ꩂꩄ-ꩋꩠ-ꩶꩺꩾ-ꪯꪱꪵꪶꪹ-ꪽꫀꫂꫛ-ꫝꫠ-ꫪꫲ-ꫴꬁ-ꬆꬉ-ꬎꬑ-ꬖꬠ-ꬦꬨ-ꬮꬰ-ꭚꭜ-ꭩ꭬꭭ꭰ-ꯢ가-힣ힰ-ퟆퟋ-ퟻ豈-舘並-龎ﬀ-ﬆﬓ-ﬗיִײַ-ﬨשׁ-זּטּ-לּמּנּסּףּפּצּ-ﮱﯓ-ﴽﵐ-ﶏﶒ-ﷇﷰ-ﷻﹰ-ﹴﹶ-ﻼＡ-Ｚａ-ｚｦ-ﾾￂ-ￇￊ-ￏￒ-ￗￚ-ￜ";
	reservedWords = {
		3: "abstract boolean byte char class double enum export extends final float goto implements import int interface long native package private protected public short static super synchronized throws transient volatile",
		5: "class enum extends super const export import",
		6: "enum",
		strict: "implements interface let package private protected public static yield",
		strictBind: "eval arguments"
	};
	ecma5AndLessKeywords = "break case catch continue debugger default do else finally for function if return switch throw try var while with null true false instanceof typeof void delete new in this";
	keywords$1 = {
		5: ecma5AndLessKeywords,
		"5module": ecma5AndLessKeywords + " export import",
		6: ecma5AndLessKeywords + " const class extends export import super"
	};
	keywordRelationalOperator = /^in(stanceof)?$/;
	nonASCIIidentifierStart = new RegExp("[" + nonASCIIidentifierStartChars + "]");
	nonASCIIidentifier = new RegExp("[" + nonASCIIidentifierStartChars + nonASCIIidentifierChars + "]");
	TokenType = function TokenType(label, conf) {
		if (conf === void 0) conf = {};
		this.label = label;
		this.keyword = conf.keyword;
		this.beforeExpr = !!conf.beforeExpr;
		this.startsExpr = !!conf.startsExpr;
		this.isLoop = !!conf.isLoop;
		this.isAssign = !!conf.isAssign;
		this.prefix = !!conf.prefix;
		this.postfix = !!conf.postfix;
		this.binop = conf.binop || null;
		this.updateContext = null;
	};
	beforeExpr = { beforeExpr: true };
	startsExpr = { startsExpr: true };
	keywords = {};
	types$1 = {
		num: new TokenType("num", startsExpr),
		regexp: new TokenType("regexp", startsExpr),
		string: new TokenType("string", startsExpr),
		name: new TokenType("name", startsExpr),
		privateId: new TokenType("privateId", startsExpr),
		eof: new TokenType("eof"),
		bracketL: new TokenType("[", {
			beforeExpr: true,
			startsExpr: true
		}),
		bracketR: new TokenType("]"),
		braceL: new TokenType("{", {
			beforeExpr: true,
			startsExpr: true
		}),
		braceR: new TokenType("}"),
		parenL: new TokenType("(", {
			beforeExpr: true,
			startsExpr: true
		}),
		parenR: new TokenType(")"),
		comma: new TokenType(",", beforeExpr),
		semi: new TokenType(";", beforeExpr),
		colon: new TokenType(":", beforeExpr),
		dot: new TokenType("."),
		question: new TokenType("?", beforeExpr),
		questionDot: new TokenType("?."),
		arrow: new TokenType("=>", beforeExpr),
		template: new TokenType("template"),
		invalidTemplate: new TokenType("invalidTemplate"),
		ellipsis: new TokenType("...", beforeExpr),
		backQuote: new TokenType("`", startsExpr),
		dollarBraceL: new TokenType("${", {
			beforeExpr: true,
			startsExpr: true
		}),
		eq: new TokenType("=", {
			beforeExpr: true,
			isAssign: true
		}),
		assign: new TokenType("_=", {
			beforeExpr: true,
			isAssign: true
		}),
		incDec: new TokenType("++/--", {
			prefix: true,
			postfix: true,
			startsExpr: true
		}),
		prefix: new TokenType("!/~", {
			beforeExpr: true,
			prefix: true,
			startsExpr: true
		}),
		logicalOR: binop("||", 1),
		logicalAND: binop("&&", 2),
		bitwiseOR: binop("|", 3),
		bitwiseXOR: binop("^", 4),
		bitwiseAND: binop("&", 5),
		equality: binop("==/!=/===/!==", 6),
		relational: binop("</>/<=/>=", 7),
		bitShift: binop("<</>>/>>>", 8),
		plusMin: new TokenType("+/-", {
			beforeExpr: true,
			binop: 9,
			prefix: true,
			startsExpr: true
		}),
		modulo: binop("%", 10),
		star: binop("*", 10),
		slash: binop("/", 10),
		starstar: new TokenType("**", { beforeExpr: true }),
		coalesce: binop("??", 1),
		_break: kw("break"),
		_case: kw("case", beforeExpr),
		_catch: kw("catch"),
		_continue: kw("continue"),
		_debugger: kw("debugger"),
		_default: kw("default", beforeExpr),
		_do: kw("do", {
			isLoop: true,
			beforeExpr: true
		}),
		_else: kw("else", beforeExpr),
		_finally: kw("finally"),
		_for: kw("for", { isLoop: true }),
		_function: kw("function", startsExpr),
		_if: kw("if"),
		_return: kw("return", beforeExpr),
		_switch: kw("switch"),
		_throw: kw("throw", beforeExpr),
		_try: kw("try"),
		_var: kw("var"),
		_const: kw("const"),
		_while: kw("while", { isLoop: true }),
		_with: kw("with"),
		_new: kw("new", {
			beforeExpr: true,
			startsExpr: true
		}),
		_this: kw("this", startsExpr),
		_super: kw("super", startsExpr),
		_class: kw("class", startsExpr),
		_extends: kw("extends", beforeExpr),
		_export: kw("export"),
		_import: kw("import", startsExpr),
		_null: kw("null", startsExpr),
		_true: kw("true", startsExpr),
		_false: kw("false", startsExpr),
		_in: kw("in", {
			beforeExpr: true,
			binop: 7
		}),
		_instanceof: kw("instanceof", {
			beforeExpr: true,
			binop: 7
		}),
		_typeof: kw("typeof", {
			beforeExpr: true,
			prefix: true,
			startsExpr: true
		}),
		_void: kw("void", {
			beforeExpr: true,
			prefix: true,
			startsExpr: true
		}),
		_delete: kw("delete", {
			beforeExpr: true,
			prefix: true,
			startsExpr: true
		})
	};
	lineBreak = /\r\n?|\n|\u2028|\u2029/;
	lineBreakG = new RegExp(lineBreak.source, "g");
	nonASCIIwhitespace = /[\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff]/;
	skipWhiteSpace = /(?:\s|\/\/.*|\/\*[^]*?\*\/)*/g;
	ref = Object.prototype;
	hasOwnProperty = ref.hasOwnProperty;
	toString = ref.toString;
	hasOwn = Object.hasOwn || (function(obj, propName) {
		return hasOwnProperty.call(obj, propName);
	});
	isArray = Array.isArray || (function(obj) {
		return toString.call(obj) === "[object Array]";
	});
	regexpCache = Object.create(null);
	loneSurrogate = /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF])/;
	Position = function Position(line, col) {
		this.line = line;
		this.column = col;
	};
	Position.prototype.offset = function offset(n) {
		return new Position(this.line, this.column + n);
	};
	SourceLocation = function SourceLocation(p, start, end) {
		this.start = start;
		this.end = end;
		if (p.sourceFile !== null) this.source = p.sourceFile;
	};
	defaultOptions = {
		ecmaVersion: null,
		sourceType: "script",
		strict: false,
		onInsertedSemicolon: null,
		onTrailingComma: null,
		allowReserved: null,
		allowReturnOutsideFunction: false,
		allowImportExportEverywhere: false,
		allowAwaitOutsideFunction: null,
		allowSuperOutsideMethod: null,
		allowHashBang: false,
		checkPrivateFields: true,
		locations: false,
		startLocation: null,
		onToken: null,
		onComment: null,
		ranges: false,
		program: null,
		sourceFile: null,
		directSourceFile: null,
		preserveParens: false
	};
	warnedAboutEcmaVersion = false;
	SCOPE_TOP = 1;
	SCOPE_FUNCTION = 2;
	SCOPE_ASYNC = 4;
	SCOPE_GENERATOR = 8;
	SCOPE_ARROW = 16;
	SCOPE_SIMPLE_CATCH = 32;
	SCOPE_SUPER = 64;
	SCOPE_DIRECT_SUPER = 128;
	SCOPE_CLASS_STATIC_BLOCK = 256;
	SCOPE_CLASS_FIELD_INIT = 512;
	SCOPE_SWITCH = 1024;
	SCOPE_VAR = SCOPE_TOP | SCOPE_FUNCTION | SCOPE_CLASS_STATIC_BLOCK;
	BIND_NONE = 0;
	BIND_VAR = 1;
	BIND_LEXICAL = 2;
	BIND_FUNCTION = 3;
	BIND_SIMPLE_CATCH = 4;
	BIND_OUTSIDE = 5;
	Parser = function Parser(options, input, startPos) {
		this.options = options = getOptions(options);
		this.sourceFile = options.sourceFile;
		this.keywords = wordsRegexp(keywords$1[options.ecmaVersion >= 6 ? 6 : options.sourceType === "module" ? "5module" : 5]);
		var reserved = "";
		if (options.allowReserved !== true) {
			reserved = reservedWords[options.ecmaVersion >= 6 ? 6 : options.ecmaVersion === 5 ? 5 : 3];
			if (options.sourceType === "module") reserved += " await";
		}
		this.reservedWords = wordsRegexp(reserved);
		var reservedStrict = (reserved ? reserved + " " : "") + reservedWords.strict;
		this.reservedWordsStrict = wordsRegexp(reservedStrict);
		this.reservedWordsStrictBind = wordsRegexp(reservedStrict + " " + reservedWords.strictBind);
		this.input = String(input);
		this.containsEsc = false;
		this.pos = startPos || 0;
		this.curLine = 1;
		if (options.startLocation) {
			this.lineStart = this.pos - options.startLocation.column;
			this.curLine = options.startLocation.line;
		} else if (startPos) {
			this.lineStart = this.input.lastIndexOf("\n", startPos - 1) + 1;
			if (this.options.locations) this.curLine = this.input.slice(0, this.lineStart).split(lineBreak).length;
		} else this.lineStart = 0;
		this.type = types$1.eof;
		this.value = null;
		this.start = this.end = this.pos;
		this.startLoc = this.endLoc = this.curPosition();
		this.lastTokEndLoc = this.lastTokStartLoc = null;
		this.lastTokStart = this.lastTokEnd = this.pos;
		this.context = this.initialContext();
		this.exprAllowed = true;
		this.inModule = options.sourceType === "module";
		this.strict = this.inModule || options.strict === true || this.strictDirective(this.pos);
		this.potentialArrowAt = -1;
		this.potentialArrowInForAwait = false;
		this.yieldPos = this.awaitPos = this.awaitIdentPos = 0;
		this.labels = [];
		this.undefinedExports = Object.create(null);
		if (this.pos === 0 && options.allowHashBang && this.input.slice(0, 2) === "#!") this.skipLineComment(2);
		this.scopeStack = [];
		this.enterScope(this.options.sourceType === "commonjs" ? SCOPE_FUNCTION : SCOPE_TOP);
		this.regexpState = null;
		this.privateNameStack = [];
	};
	prototypeAccessors = {
		inFunction: { configurable: true },
		inGenerator: { configurable: true },
		inAsync: { configurable: true },
		canAwait: { configurable: true },
		allowReturn: { configurable: true },
		allowSuper: { configurable: true },
		allowDirectSuper: { configurable: true },
		treatFunctionsAsVar: { configurable: true },
		allowNewDotTarget: { configurable: true },
		allowUsing: { configurable: true },
		inClassStaticBlock: { configurable: true }
	};
	Parser.prototype.parse = function parse() {
		var this$1$1 = this;
		var node = this.options.program || this.startNode();
		this.nextToken();
		return this.catchStackOverflow(function() {
			return this$1$1.parseTopLevel(node);
		});
	};
	prototypeAccessors.inFunction.get = function() {
		return (this.currentVarScope().flags & SCOPE_FUNCTION) > 0;
	};
	prototypeAccessors.inGenerator.get = function() {
		return (this.currentVarScope().flags & SCOPE_GENERATOR) > 0;
	};
	prototypeAccessors.inAsync.get = function() {
		return (this.currentVarScope().flags & SCOPE_ASYNC) > 0;
	};
	prototypeAccessors.canAwait.get = function() {
		for (var i = this.scopeStack.length - 1; i >= 0; i--) {
			var flags = this.scopeStack[i].flags;
			if (flags & (SCOPE_CLASS_STATIC_BLOCK | SCOPE_CLASS_FIELD_INIT)) return false;
			if (flags & SCOPE_FUNCTION) return (flags & SCOPE_ASYNC) > 0;
		}
		return this.inModule && this.options.ecmaVersion >= 13 || this.options.allowAwaitOutsideFunction;
	};
	prototypeAccessors.allowReturn.get = function() {
		if (this.inFunction) return true;
		if (this.options.allowReturnOutsideFunction && this.currentVarScope().flags & SCOPE_TOP) return true;
		return false;
	};
	prototypeAccessors.allowSuper.get = function() {
		return (this.currentThisScope().flags & SCOPE_SUPER) > 0 || this.options.allowSuperOutsideMethod;
	};
	prototypeAccessors.allowDirectSuper.get = function() {
		return (this.currentThisScope().flags & SCOPE_DIRECT_SUPER) > 0;
	};
	prototypeAccessors.treatFunctionsAsVar.get = function() {
		return this.treatFunctionsAsVarInScope(this.currentScope());
	};
	prototypeAccessors.allowNewDotTarget.get = function() {
		for (var i = this.scopeStack.length - 1; i >= 0; i--) {
			var flags = this.scopeStack[i].flags;
			if (flags & (SCOPE_CLASS_STATIC_BLOCK | SCOPE_CLASS_FIELD_INIT) || flags & SCOPE_FUNCTION && !(flags & SCOPE_ARROW)) return true;
		}
		return false;
	};
	prototypeAccessors.allowUsing.get = function() {
		var flags = this.currentScope().flags;
		if (flags & SCOPE_SWITCH) return false;
		if (!this.inModule && flags & SCOPE_TOP) return false;
		return true;
	};
	prototypeAccessors.inClassStaticBlock.get = function() {
		return (this.currentVarScope().flags & SCOPE_CLASS_STATIC_BLOCK) > 0;
	};
	Parser.extend = function extend() {
		var plugins = [], len = arguments.length;
		while (len--) plugins[len] = arguments[len];
		var cls = this;
		for (var i = 0; i < plugins.length; i++) cls = plugins[i](cls);
		return cls;
	};
	Parser.parse = function parse(input, options) {
		return new this(options, input).parse();
	};
	Parser.parseExpressionAt = function parseExpressionAt(input, pos, options) {
		var parser = new this(options, input, pos);
		parser.nextToken();
		return parser.parseExpression();
	};
	Parser.tokenizer = function tokenizer(input, options) {
		return new this(options, input);
	};
	Object.defineProperties(Parser.prototype, prototypeAccessors);
	pp$9 = Parser.prototype;
	literal = /^(?:'((?:\\[^]|[^'\\])*?)'|"((?:\\[^]|[^"\\])*?)")/;
	pp$9.strictDirective = function(start) {
		if (this.options.ecmaVersion < 5) return false;
		for (;;) {
			skipWhiteSpace.lastIndex = start;
			start += skipWhiteSpace.exec(this.input)[0].length;
			var match = literal.exec(this.input.slice(start));
			if (!match) return false;
			if ((match[1] || match[2]) === "use strict") {
				skipWhiteSpace.lastIndex = start + match[0].length;
				var spaceAfter = skipWhiteSpace.exec(this.input), end = spaceAfter.index + spaceAfter[0].length;
				var next = this.input.charAt(end);
				return next === ";" || next === "}" || lineBreak.test(spaceAfter[0]) && !(/[(`.[+\-/*%<>=,?^&]/.test(next) || next === "!" && this.input.charAt(end + 1) === "=" || next === "i" && keywordOpAt(this, end));
			}
			start += match[0].length;
			skipWhiteSpace.lastIndex = start;
			start += skipWhiteSpace.exec(this.input)[0].length;
			if (this.input[start] === ";") start++;
		}
	};
	pp$9.eat = function(type) {
		if (this.type === type) {
			this.next();
			return true;
		} else return false;
	};
	pp$9.isContextual = function(name) {
		return this.type === types$1.name && this.value === name && !this.containsEsc;
	};
	pp$9.eatContextual = function(name) {
		if (!this.isContextual(name)) return false;
		this.next();
		return true;
	};
	pp$9.catchStackOverflow = function(f) {
		try {
			return f();
		} catch (e) {
			if (e instanceof Error && (/\bstack\b.*\b(exceeded|overflow)\b/i.test(e.message) || /\btoo much recursion\b/i.test(e.message))) this.raise(this.start, "Not enough stack space to parse input");
			else throw e;
		}
	};
	pp$9.expectContextual = function(name) {
		if (!this.eatContextual(name)) this.unexpected();
	};
	pp$9.canInsertSemicolon = function() {
		return this.type === types$1.eof || this.type === types$1.braceR || lineBreak.test(this.input.slice(this.lastTokEnd, this.start));
	};
	pp$9.insertSemicolon = function() {
		if (this.canInsertSemicolon()) {
			if (this.options.onInsertedSemicolon) this.options.onInsertedSemicolon(this.lastTokEnd, this.lastTokEndLoc);
			return true;
		}
	};
	pp$9.semicolon = function() {
		if (!this.eat(types$1.semi) && !this.insertSemicolon()) this.unexpected();
	};
	pp$9.afterTrailingComma = function(tokType, notNext) {
		if (this.type === tokType) {
			if (this.options.onTrailingComma) this.options.onTrailingComma(this.lastTokStart, this.lastTokStartLoc);
			if (!notNext) this.next();
			return true;
		}
	};
	pp$9.expect = function(type) {
		this.eat(type) || this.unexpected();
	};
	pp$9.unexpected = function(pos) {
		this.raise(pos != null ? pos : this.start, "Unexpected token");
	};
	DestructuringErrors = function DestructuringErrors() {
		this.shorthandAssign = this.trailingComma = this.parenthesizedAssign = this.parenthesizedBind = this.doubleProto = -1;
	};
	pp$9.checkPatternErrors = function(refDestructuringErrors, isAssign) {
		if (!refDestructuringErrors) return;
		if (refDestructuringErrors.trailingComma > -1) this.raiseRecoverable(refDestructuringErrors.trailingComma, "Comma is not permitted after the rest element");
		var parens = isAssign ? refDestructuringErrors.parenthesizedAssign : refDestructuringErrors.parenthesizedBind;
		if (parens > -1) this.raiseRecoverable(parens, isAssign ? "Assigning to rvalue" : "Parenthesized pattern");
	};
	pp$9.checkExpressionErrors = function(refDestructuringErrors, andThrow) {
		if (!refDestructuringErrors) return false;
		var shorthandAssign = refDestructuringErrors.shorthandAssign;
		var doubleProto = refDestructuringErrors.doubleProto;
		if (!andThrow) return shorthandAssign >= 0 || doubleProto >= 0;
		if (shorthandAssign >= 0) this.raise(shorthandAssign, "Shorthand property assignments are valid only in destructuring patterns");
		if (doubleProto >= 0) this.raiseRecoverable(doubleProto, "Redefinition of __proto__ property");
	};
	pp$9.checkYieldAwaitInDefaultParams = function() {
		if (this.yieldPos && (!this.awaitPos || this.yieldPos < this.awaitPos)) this.raise(this.yieldPos, "Yield expression cannot be a default value");
		if (this.awaitPos) this.raise(this.awaitPos, "Await expression cannot be a default value");
	};
	pp$9.isSimpleAssignTarget = function(expr) {
		if (expr.type === "ParenthesizedExpression") return this.isSimpleAssignTarget(expr.expression);
		return expr.type === "Identifier" || expr.type === "MemberExpression";
	};
	pp$8 = Parser.prototype;
	pp$8.parseTopLevel = function(node) {
		var exports$1 = Object.create(null);
		if (!node.body) node.body = [];
		while (this.type !== types$1.eof) {
			var stmt = this.parseStatement(null, true, exports$1);
			node.body.push(stmt);
		}
		if (this.inModule) for (var i = 0, list = Object.keys(this.undefinedExports); i < list.length; i += 1) {
			var name = list[i];
			this.raiseRecoverable(this.undefinedExports[name].start, "Export '" + name + "' is not defined");
		}
		this.adaptDirectivePrologue(node.body);
		this.next();
		node.sourceType = this.options.sourceType === "commonjs" ? "script" : this.options.sourceType;
		return this.finishNode(node, "Program");
	};
	loopLabel = { kind: "loop" };
	switchLabel = { kind: "switch" };
	pp$8.isLet = function(context) {
		if (this.options.ecmaVersion < 6 || !this.isContextual("let")) return false;
		skipWhiteSpace.lastIndex = this.pos;
		var skip = skipWhiteSpace.exec(this.input);
		var next = this.pos + skip[0].length, nextCh = this.fullCharCodeAt(next);
		if (nextCh === 91 || nextCh === 92) return true;
		if (context) return false;
		if (nextCh === 123) return true;
		if (isIdentifierStart(nextCh)) {
			var start = next;
			do
				next += nextCh <= 65535 ? 1 : 2;
			while (isIdentifierChar(nextCh = this.fullCharCodeAt(next)));
			if (nextCh === 92) return true;
			var ident = this.input.slice(start, next);
			if (!keywordRelationalOperator.test(ident)) return true;
		}
		return false;
	};
	pp$8.isAsyncFunction = function() {
		if (this.options.ecmaVersion < 8 || !this.isContextual("async")) return false;
		skipWhiteSpace.lastIndex = this.pos;
		var skip = skipWhiteSpace.exec(this.input);
		var next = this.pos + skip[0].length, after;
		return !lineBreak.test(this.input.slice(this.pos, next)) && this.input.slice(next, next + 8) === "function" && (next + 8 === this.input.length || !(isIdentifierChar(after = this.fullCharCodeAt(next + 8)) || after === 92));
	};
	pp$8.isUsingKeyword = function(isAwaitUsing, isFor) {
		if (this.options.ecmaVersion < 17 || !this.isContextual(isAwaitUsing ? "await" : "using")) return false;
		skipWhiteSpace.lastIndex = this.pos;
		var skip = skipWhiteSpace.exec(this.input);
		var next = this.pos + skip[0].length;
		if (lineBreak.test(this.input.slice(this.pos, next))) return false;
		if (isAwaitUsing) {
			var usingEndPos = next + 5, after;
			if (this.input.slice(next, usingEndPos) !== "using" || usingEndPos === this.input.length || isIdentifierChar(after = this.fullCharCodeAt(usingEndPos)) || after === 92) return false;
			skipWhiteSpace.lastIndex = usingEndPos;
			var skipAfterUsing = skipWhiteSpace.exec(this.input);
			next = usingEndPos + skipAfterUsing[0].length;
			if (skipAfterUsing && lineBreak.test(this.input.slice(usingEndPos, next))) return false;
		}
		var ch = this.fullCharCodeAt(next);
		if (!isIdentifierStart(ch) && ch !== 92) return false;
		var idStart = next;
		do
			next += ch <= 65535 ? 1 : 2;
		while (isIdentifierChar(ch = this.fullCharCodeAt(next)));
		if (ch === 92) return true;
		var id = this.input.slice(idStart, next);
		if (keywordRelationalOperator.test(id)) return false;
		if (isFor && !isAwaitUsing && id === "of") {
			skipWhiteSpace.lastIndex = next;
			var skipAfterOf = skipWhiteSpace.exec(this.input);
			next = next + skipAfterOf[0].length;
			if (this.input.charCodeAt(next) !== 61 || (ch = this.input.charCodeAt(next + 1)) === 61 || ch === 62) return false;
		}
		return true;
	};
	pp$8.isAwaitUsing = function(isFor) {
		return this.isUsingKeyword(true, isFor);
	};
	pp$8.isUsing = function(isFor) {
		return this.isUsingKeyword(false, isFor);
	};
	pp$8.parseStatement = function(context, topLevel, exports$1) {
		var starttype = this.type, node = this.startNode(), kind;
		if (this.isLet(context)) {
			starttype = types$1._var;
			kind = "let";
		}
		switch (starttype) {
			case types$1._break:
			case types$1._continue: return this.parseBreakContinueStatement(node, starttype.keyword);
			case types$1._debugger: return this.parseDebuggerStatement(node);
			case types$1._do: return this.parseDoStatement(node);
			case types$1._for: return this.parseForStatement(node);
			case types$1._function:
				if (context && (this.strict || context !== "if" && context !== "label") && this.options.ecmaVersion >= 6) this.unexpected();
				return this.parseFunctionStatement(node, false, !context);
			case types$1._class:
				if (context) this.unexpected();
				return this.parseClass(node, true);
			case types$1._if: return this.parseIfStatement(node);
			case types$1._return: return this.parseReturnStatement(node);
			case types$1._switch: return this.parseSwitchStatement(node);
			case types$1._throw: return this.parseThrowStatement(node);
			case types$1._try: return this.parseTryStatement(node);
			case types$1._const:
			case types$1._var:
				kind = kind || this.value;
				if (context && kind !== "var") this.unexpected();
				return this.parseVarStatement(node, kind);
			case types$1._while: return this.parseWhileStatement(node);
			case types$1._with: return this.parseWithStatement(node);
			case types$1.braceL: return this.parseBlock(true, node);
			case types$1.semi: return this.parseEmptyStatement(node);
			case types$1._export:
			case types$1._import:
				if (this.options.ecmaVersion > 10 && starttype === types$1._import) {
					skipWhiteSpace.lastIndex = this.pos;
					var skip = skipWhiteSpace.exec(this.input);
					var next = this.pos + skip[0].length, nextCh = this.input.charCodeAt(next);
					if (nextCh === 40 || nextCh === 46) return this.parseExpressionStatement(node, this.parseExpression());
				}
				if (!this.options.allowImportExportEverywhere) {
					if (!topLevel) this.raise(this.start, "'import' and 'export' may only appear at the top level");
					if (!this.inModule) this.raise(this.start, "'import' and 'export' may appear only with 'sourceType: module'");
				}
				return starttype === types$1._import ? this.parseImport(node) : this.parseExport(node, exports$1);
			default:
				if (this.isAsyncFunction()) {
					if (context) this.unexpected();
					this.next();
					return this.parseFunctionStatement(node, true, !context);
				}
				var usingKind = this.isAwaitUsing(false) ? "await using" : this.isUsing(false) ? "using" : null;
				if (usingKind) {
					if (!this.allowUsing) this.raise(this.start, "Using declaration cannot appear in the top level when source type is `script` or in the bare case statement");
					if (context) this.raise(this.start, "Using declaration is not allowed in single-statement positions");
					if (usingKind === "await using") {
						if (!this.canAwait) this.raise(this.start, "Await using cannot appear outside of async function");
						this.next();
					}
					this.next();
					this.parseVar(node, false, usingKind);
					this.semicolon();
					return this.finishNode(node, "VariableDeclaration");
				}
				var maybeName = this.value, expr = this.parseExpression();
				if (starttype === types$1.name && expr.type === "Identifier" && this.eat(types$1.colon)) return this.parseLabeledStatement(node, maybeName, expr, context);
				else return this.parseExpressionStatement(node, expr);
		}
	};
	pp$8.parseBreakContinueStatement = function(node, keyword) {
		var isBreak = keyword === "break";
		this.next();
		if (this.eat(types$1.semi) || this.insertSemicolon()) node.label = null;
		else if (this.type !== types$1.name) this.unexpected();
		else {
			node.label = this.parseIdent();
			this.semicolon();
		}
		var i = 0;
		for (; i < this.labels.length; ++i) {
			var lab = this.labels[i];
			if (node.label == null || lab.name === node.label.name) {
				if (lab.kind != null && (isBreak || lab.kind === "loop")) break;
				if (node.label && isBreak) break;
			}
		}
		if (i === this.labels.length) this.raise(node.start, "Unsyntactic " + keyword);
		return this.finishNode(node, isBreak ? "BreakStatement" : "ContinueStatement");
	};
	pp$8.parseDebuggerStatement = function(node) {
		this.next();
		this.semicolon();
		return this.finishNode(node, "DebuggerStatement");
	};
	pp$8.parseDoStatement = function(node) {
		this.next();
		this.labels.push(loopLabel);
		node.body = this.parseStatement("do");
		this.labels.pop();
		this.expect(types$1._while);
		node.test = this.parseParenExpression();
		if (this.options.ecmaVersion >= 6) this.eat(types$1.semi);
		else this.semicolon();
		return this.finishNode(node, "DoWhileStatement");
	};
	pp$8.parseForStatement = function(node) {
		this.next();
		var awaitAt = this.options.ecmaVersion >= 9 && this.canAwait && this.eatContextual("await") ? this.lastTokStart : -1;
		this.labels.push(loopLabel);
		this.enterScope(0);
		this.expect(types$1.parenL);
		if (this.type === types$1.semi) {
			if (awaitAt > -1) this.unexpected(awaitAt);
			return this.parseFor(node, null);
		}
		var isLet = this.isLet();
		if (this.type === types$1._var || this.type === types$1._const || isLet) {
			var init$1 = this.startNode(), kind = isLet ? "let" : this.value;
			this.next();
			this.parseVar(init$1, true, kind);
			this.finishNode(init$1, "VariableDeclaration");
			return this.parseForAfterInit(node, init$1, awaitAt);
		}
		var startsWithLet = this.isContextual("let"), isForOf = false;
		var usingKind = this.isUsing(true) ? "using" : this.isAwaitUsing(true) ? "await using" : null;
		if (usingKind) {
			var init$2 = this.startNode();
			this.next();
			if (usingKind === "await using") {
				if (!this.canAwait) this.raise(this.start, "Await using cannot appear outside of async function");
				this.next();
			}
			this.parseVar(init$2, true, usingKind);
			this.finishNode(init$2, "VariableDeclaration");
			return this.parseForAfterInit(node, init$2, awaitAt);
		}
		var containsEsc = this.containsEsc;
		var refDestructuringErrors = new DestructuringErrors();
		var initPos = this.start;
		var init = awaitAt > -1 ? this.parseExprSubscripts(refDestructuringErrors, "await") : this.parseExpression(true, refDestructuringErrors);
		if (this.type === types$1._in || (isForOf = this.options.ecmaVersion >= 6 && this.isContextual("of"))) {
			if (awaitAt > -1) {
				if (this.type === types$1._in) this.unexpected(awaitAt);
				node.await = true;
			} else if (isForOf && this.options.ecmaVersion >= 8) {
				if (init.start === initPos && !containsEsc && init.type === "Identifier" && init.name === "async") this.unexpected();
				else if (this.options.ecmaVersion >= 9) node.await = false;
			}
			if (startsWithLet && isForOf) this.raise(init.start, "The left-hand side of a for-of loop may not start with 'let'.");
			this.toAssignable(init, false, refDestructuringErrors);
			this.checkLValPattern(init);
			return this.parseForIn(node, init);
		} else this.checkExpressionErrors(refDestructuringErrors, true);
		if (awaitAt > -1) this.unexpected(awaitAt);
		return this.parseFor(node, init);
	};
	pp$8.parseForAfterInit = function(node, init, awaitAt) {
		if ((this.type === types$1._in || this.options.ecmaVersion >= 6 && this.isContextual("of")) && init.declarations.length === 1) {
			if (this.type === types$1._in) {
				if ((init.kind === "using" || init.kind === "await using") && !init.declarations[0].init) this.raise(this.start, "Using declaration is not allowed in for-in loops");
				if (this.options.ecmaVersion >= 9 && awaitAt > -1) this.unexpected(awaitAt);
			} else if (this.options.ecmaVersion >= 9) node.await = awaitAt > -1;
			return this.parseForIn(node, init);
		}
		if (awaitAt > -1) this.unexpected(awaitAt);
		return this.parseFor(node, init);
	};
	pp$8.parseFunctionStatement = function(node, isAsync, declarationPosition) {
		this.next();
		return this.parseFunction(node, FUNC_STATEMENT | (declarationPosition ? 0 : FUNC_HANGING_STATEMENT), false, isAsync);
	};
	pp$8.parseIfStatement = function(node) {
		this.next();
		node.test = this.parseParenExpression();
		node.consequent = this.parseStatement("if");
		node.alternate = this.eat(types$1._else) ? this.parseStatement("if") : null;
		return this.finishNode(node, "IfStatement");
	};
	pp$8.parseReturnStatement = function(node) {
		if (!this.allowReturn) this.raise(this.start, "'return' outside of function");
		this.next();
		if (this.eat(types$1.semi) || this.insertSemicolon()) node.argument = null;
		else {
			node.argument = this.parseExpression();
			this.semicolon();
		}
		return this.finishNode(node, "ReturnStatement");
	};
	pp$8.parseSwitchStatement = function(node) {
		this.next();
		node.discriminant = this.parseParenExpression();
		node.cases = [];
		this.expect(types$1.braceL);
		this.labels.push(switchLabel);
		this.enterScope(SCOPE_SWITCH);
		var cur;
		for (var sawDefault = false; this.type !== types$1.braceR;) if (this.type === types$1._case || this.type === types$1._default) {
			var isCase = this.type === types$1._case;
			if (cur) this.finishNode(cur, "SwitchCase");
			node.cases.push(cur = this.startNode());
			cur.consequent = [];
			this.next();
			if (isCase) cur.test = this.parseExpression();
			else {
				if (sawDefault) this.raiseRecoverable(this.lastTokStart, "Multiple default clauses");
				sawDefault = true;
				cur.test = null;
			}
			this.expect(types$1.colon);
		} else {
			if (!cur) this.unexpected();
			cur.consequent.push(this.parseStatement(null));
		}
		this.exitScope();
		if (cur) this.finishNode(cur, "SwitchCase");
		this.next();
		this.labels.pop();
		return this.finishNode(node, "SwitchStatement");
	};
	pp$8.parseThrowStatement = function(node) {
		this.next();
		if (lineBreak.test(this.input.slice(this.lastTokEnd, this.start))) this.raise(this.lastTokEnd, "Illegal newline after throw");
		node.argument = this.parseExpression();
		this.semicolon();
		return this.finishNode(node, "ThrowStatement");
	};
	empty$1 = [];
	pp$8.parseCatchClauseParam = function() {
		var param = this.parseBindingAtom();
		var simple = param.type === "Identifier";
		this.enterScope(simple ? SCOPE_SIMPLE_CATCH : 0);
		this.checkLValPattern(param, simple ? BIND_SIMPLE_CATCH : BIND_LEXICAL);
		this.expect(types$1.parenR);
		return param;
	};
	pp$8.parseTryStatement = function(node) {
		this.next();
		node.block = this.parseBlock();
		node.handler = null;
		if (this.type === types$1._catch) {
			var clause = this.startNode();
			this.next();
			if (this.eat(types$1.parenL)) clause.param = this.parseCatchClauseParam();
			else {
				if (this.options.ecmaVersion < 10) this.unexpected();
				clause.param = null;
				this.enterScope(0);
			}
			clause.body = this.parseBlock(false);
			this.exitScope();
			node.handler = this.finishNode(clause, "CatchClause");
		}
		node.finalizer = this.eat(types$1._finally) ? this.parseBlock() : null;
		if (!node.handler && !node.finalizer) this.raise(node.start, "Missing catch or finally clause");
		return this.finishNode(node, "TryStatement");
	};
	pp$8.parseVarStatement = function(node, kind, allowMissingInitializer) {
		this.next();
		this.parseVar(node, false, kind, allowMissingInitializer);
		this.semicolon();
		return this.finishNode(node, "VariableDeclaration");
	};
	pp$8.parseWhileStatement = function(node) {
		this.next();
		node.test = this.parseParenExpression();
		this.labels.push(loopLabel);
		node.body = this.parseStatement("while");
		this.labels.pop();
		return this.finishNode(node, "WhileStatement");
	};
	pp$8.parseWithStatement = function(node) {
		if (this.strict) this.raise(this.start, "'with' in strict mode");
		this.next();
		node.object = this.parseParenExpression();
		node.body = this.parseStatement("with");
		return this.finishNode(node, "WithStatement");
	};
	pp$8.parseEmptyStatement = function(node) {
		this.next();
		return this.finishNode(node, "EmptyStatement");
	};
	pp$8.parseLabeledStatement = function(node, maybeName, expr, context) {
		for (var i$1 = 0, list = this.labels; i$1 < list.length; i$1 += 1) if (list[i$1].name === maybeName) this.raise(expr.start, "Label '" + maybeName + "' is already declared");
		var kind = this.type.isLoop ? "loop" : this.type === types$1._switch ? "switch" : null;
		for (var i = this.labels.length - 1; i >= 0; i--) {
			var label$1 = this.labels[i];
			if (label$1.statementStart === node.start) {
				label$1.statementStart = this.start;
				label$1.kind = kind;
			} else break;
		}
		this.labels.push({
			name: maybeName,
			kind,
			statementStart: this.start
		});
		node.body = this.parseStatement(context ? context.indexOf("label") === -1 ? context + "label" : context : "label");
		this.labels.pop();
		node.label = expr;
		return this.finishNode(node, "LabeledStatement");
	};
	pp$8.parseExpressionStatement = function(node, expr) {
		node.expression = expr;
		this.semicolon();
		return this.finishNode(node, "ExpressionStatement");
	};
	pp$8.parseBlock = function(createNewLexicalScope, node, exitStrict) {
		if (createNewLexicalScope === void 0) createNewLexicalScope = true;
		if (node === void 0) node = this.startNode();
		node.body = [];
		this.expect(types$1.braceL);
		if (createNewLexicalScope) this.enterScope(0);
		while (this.type !== types$1.braceR) {
			var stmt = this.parseStatement(null);
			node.body.push(stmt);
		}
		if (exitStrict) this.strict = false;
		this.next();
		if (createNewLexicalScope) this.exitScope();
		return this.finishNode(node, "BlockStatement");
	};
	pp$8.parseFor = function(node, init) {
		node.init = init;
		this.expect(types$1.semi);
		node.test = this.type === types$1.semi ? null : this.parseExpression();
		this.expect(types$1.semi);
		node.update = this.type === types$1.parenR ? null : this.parseExpression();
		this.expect(types$1.parenR);
		node.body = this.parseStatement("for");
		this.exitScope();
		this.labels.pop();
		return this.finishNode(node, "ForStatement");
	};
	pp$8.parseForIn = function(node, init) {
		var isForIn = this.type === types$1._in;
		this.next();
		if (init.type === "VariableDeclaration" && init.declarations[0].init != null && (!isForIn || this.options.ecmaVersion < 8 || this.strict || init.kind !== "var" || init.declarations[0].id.type !== "Identifier")) this.raise(init.start, (isForIn ? "for-in" : "for-of") + " loop variable declaration may not have an initializer");
		node.left = init;
		node.right = isForIn ? this.parseExpression() : this.parseMaybeAssign();
		this.expect(types$1.parenR);
		node.body = this.parseStatement("for");
		this.exitScope();
		this.labels.pop();
		return this.finishNode(node, isForIn ? "ForInStatement" : "ForOfStatement");
	};
	pp$8.parseVar = function(node, isFor, kind, allowMissingInitializer) {
		node.declarations = [];
		node.kind = kind;
		for (;;) {
			var decl = this.startNode();
			this.parseVarId(decl, kind);
			if (this.eat(types$1.eq)) decl.init = this.parseMaybeAssign(isFor);
			else if (!allowMissingInitializer && kind === "const" && !(this.type === types$1._in || this.options.ecmaVersion >= 6 && this.isContextual("of"))) this.unexpected();
			else if (!allowMissingInitializer && (kind === "using" || kind === "await using") && this.options.ecmaVersion >= 17 && this.type !== types$1._in && !this.isContextual("of")) this.raise(this.lastTokEnd, "Missing initializer in " + kind + " declaration");
			else if (!allowMissingInitializer && decl.id.type !== "Identifier" && !(isFor && (this.type === types$1._in || this.isContextual("of")))) this.raise(this.lastTokEnd, "Complex binding patterns require an initialization value");
			else decl.init = null;
			node.declarations.push(this.finishNode(decl, "VariableDeclarator"));
			if (!this.eat(types$1.comma)) break;
		}
		return node;
	};
	pp$8.parseVarId = function(decl, kind) {
		decl.id = kind === "using" || kind === "await using" ? this.parseIdent() : this.parseBindingAtom();
		this.checkLValPattern(decl.id, kind === "var" ? BIND_VAR : BIND_LEXICAL, false);
	};
	FUNC_STATEMENT = 1;
	FUNC_HANGING_STATEMENT = 2;
	FUNC_NULLABLE_ID = 4;
	pp$8.parseFunction = function(node, statement, allowExpressionBody, isAsync, forInit) {
		this.initFunction(node);
		if (this.options.ecmaVersion >= 9 || this.options.ecmaVersion >= 6 && !isAsync) {
			if (this.type === types$1.star && statement & FUNC_HANGING_STATEMENT) this.unexpected();
			node.generator = this.eat(types$1.star);
		}
		if (this.options.ecmaVersion >= 8) node.async = !!isAsync;
		if (statement & FUNC_STATEMENT) {
			node.id = statement & FUNC_NULLABLE_ID && this.type !== types$1.name ? null : this.parseIdent();
			if (node.id && !(statement & FUNC_HANGING_STATEMENT)) this.checkLValSimple(node.id, this.strict || node.generator || node.async ? this.treatFunctionsAsVar ? BIND_VAR : BIND_LEXICAL : BIND_FUNCTION);
		}
		var oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;
		this.yieldPos = 0;
		this.awaitPos = 0;
		this.awaitIdentPos = 0;
		this.enterScope(functionFlags(node.async, node.generator));
		if (!(statement & FUNC_STATEMENT)) node.id = this.type === types$1.name ? this.parseIdent() : null;
		this.parseFunctionParams(node);
		this.parseFunctionBody(node, allowExpressionBody, false, forInit);
		this.yieldPos = oldYieldPos;
		this.awaitPos = oldAwaitPos;
		this.awaitIdentPos = oldAwaitIdentPos;
		return this.finishNode(node, statement & FUNC_STATEMENT ? "FunctionDeclaration" : "FunctionExpression");
	};
	pp$8.parseFunctionParams = function(node) {
		this.expect(types$1.parenL);
		node.params = this.parseBindingList(types$1.parenR, false, this.options.ecmaVersion >= 8);
		this.checkYieldAwaitInDefaultParams();
	};
	pp$8.parseClass = function(node, isStatement) {
		this.next();
		var oldStrict = this.strict;
		this.strict = true;
		this.parseClassId(node, isStatement);
		this.parseClassSuper(node);
		var privateNameMap = this.enterClassBody();
		var classBody = this.startNode();
		var hadConstructor = false;
		classBody.body = [];
		this.expect(types$1.braceL);
		while (this.type !== types$1.braceR) {
			var element = this.parseClassElement(node.superClass !== null);
			if (element) {
				classBody.body.push(element);
				if (element.type === "MethodDefinition" && element.kind === "constructor") {
					if (hadConstructor) this.raiseRecoverable(element.start, "Duplicate constructor in the same class");
					hadConstructor = true;
				} else if (element.key && element.key.type === "PrivateIdentifier" && isPrivateNameConflicted(privateNameMap, element)) this.raiseRecoverable(element.key.start, "Identifier '#" + element.key.name + "' has already been declared");
			}
		}
		this.strict = oldStrict;
		this.next();
		node.body = this.finishNode(classBody, "ClassBody");
		this.exitClassBody();
		return this.finishNode(node, isStatement ? "ClassDeclaration" : "ClassExpression");
	};
	pp$8.parseClassElement = function(constructorAllowsSuper) {
		if (this.eat(types$1.semi)) return null;
		var ecmaVersion = this.options.ecmaVersion;
		var node = this.startNode();
		var keyName = "";
		var isGenerator = false;
		var isAsync = false;
		var kind = "method";
		var isStatic = false;
		if (this.eatContextual("static")) {
			if (ecmaVersion >= 13 && this.eat(types$1.braceL)) {
				this.parseClassStaticBlock(node);
				return node;
			}
			if (this.isClassElementNameStart() || this.type === types$1.star) isStatic = true;
			else keyName = "static";
		}
		node.static = isStatic;
		if (!keyName && ecmaVersion >= 8 && this.eatContextual("async")) {
			if ((this.isClassElementNameStart() || this.type === types$1.star) && !this.canInsertSemicolon()) isAsync = true;
			else keyName = "async";
		}
		if (!keyName && (ecmaVersion >= 9 || !isAsync) && this.eat(types$1.star)) isGenerator = true;
		if (!keyName && !isAsync && !isGenerator) {
			var lastValue = this.value;
			if (this.eatContextual("get") || this.eatContextual("set")) {
				if (this.isClassElementNameStart()) kind = lastValue;
				else keyName = lastValue;
			}
		}
		if (keyName) {
			node.computed = false;
			node.key = this.startNodeAt(this.lastTokStart, this.lastTokStartLoc);
			node.key.name = keyName;
			this.finishNode(node.key, "Identifier");
		} else this.parseClassElementName(node);
		if (ecmaVersion < 13 || this.type === types$1.parenL || kind !== "method" || isGenerator || isAsync) {
			var isConstructor = !node.static && checkKeyName(node, "constructor");
			var allowsDirectSuper = isConstructor && constructorAllowsSuper;
			if (isConstructor && kind !== "method") this.raise(node.key.start, "Constructor can't have get/set modifier");
			node.kind = isConstructor ? "constructor" : kind;
			this.parseClassMethod(node, isGenerator, isAsync, allowsDirectSuper);
		} else this.parseClassField(node);
		return node;
	};
	pp$8.isClassElementNameStart = function() {
		return this.type === types$1.name || this.type === types$1.privateId || this.type === types$1.num || this.type === types$1.string || this.type === types$1.bracketL || this.type.keyword;
	};
	pp$8.parseClassElementName = function(element) {
		if (this.type === types$1.privateId) {
			if (this.value === "constructor") this.raise(this.start, "Classes can't have an element named '#constructor'");
			element.computed = false;
			element.key = this.parsePrivateIdent();
		} else this.parsePropertyName(element);
	};
	pp$8.parseClassMethod = function(method, isGenerator, isAsync, allowsDirectSuper) {
		var key = method.key;
		if (method.kind === "constructor") {
			if (isGenerator) this.raise(key.start, "Constructor can't be a generator");
			if (isAsync) this.raise(key.start, "Constructor can't be an async method");
		} else if (method.static && checkKeyName(method, "prototype")) this.raise(key.start, "Classes may not have a static property named prototype");
		var value = method.value = this.parseMethod(isGenerator, isAsync, allowsDirectSuper);
		if (method.kind === "get" && value.params.length !== 0) this.raiseRecoverable(value.start, "getter should have no params");
		if (method.kind === "set" && value.params.length !== 1) this.raiseRecoverable(value.start, "setter should have exactly one param");
		if (method.kind === "set" && value.params[0].type === "RestElement") this.raiseRecoverable(value.params[0].start, "Setter cannot use rest params");
		return this.finishNode(method, "MethodDefinition");
	};
	pp$8.parseClassField = function(field) {
		if (checkKeyName(field, "constructor")) this.raise(field.key.start, "Classes can't have a field named 'constructor'");
		else if (field.static && checkKeyName(field, "prototype")) this.raise(field.key.start, "Classes can't have a static field named 'prototype'");
		if (this.eat(types$1.eq)) {
			this.enterScope(SCOPE_CLASS_FIELD_INIT | SCOPE_SUPER);
			field.value = this.parseMaybeAssign();
			this.exitScope();
		} else field.value = null;
		this.semicolon();
		return this.finishNode(field, "PropertyDefinition");
	};
	pp$8.parseClassStaticBlock = function(node) {
		node.body = [];
		var oldLabels = this.labels;
		this.labels = [];
		this.enterScope(SCOPE_CLASS_STATIC_BLOCK | SCOPE_SUPER);
		while (this.type !== types$1.braceR) {
			var stmt = this.parseStatement(null);
			node.body.push(stmt);
		}
		this.next();
		this.exitScope();
		this.labels = oldLabels;
		return this.finishNode(node, "StaticBlock");
	};
	pp$8.parseClassId = function(node, isStatement) {
		if (this.type === types$1.name) {
			node.id = this.parseIdent();
			if (isStatement) this.checkLValSimple(node.id, BIND_LEXICAL, false);
		} else {
			if (isStatement === true) this.unexpected();
			node.id = null;
		}
	};
	pp$8.parseClassSuper = function(node) {
		node.superClass = this.eat(types$1._extends) ? this.parseExprSubscripts(null, false) : null;
	};
	pp$8.enterClassBody = function() {
		var element = {
			declared: Object.create(null),
			used: []
		};
		this.privateNameStack.push(element);
		return element.declared;
	};
	pp$8.exitClassBody = function() {
		var ref = this.privateNameStack.pop();
		var declared = ref.declared;
		var used = ref.used;
		if (!this.options.checkPrivateFields) return;
		var len = this.privateNameStack.length;
		var parent = len === 0 ? null : this.privateNameStack[len - 1];
		for (var i = 0; i < used.length; ++i) {
			var id = used[i];
			if (!hasOwn(declared, id.name)) {
				if (parent) parent.used.push(id);
				else this.raiseRecoverable(id.start, "Private field '#" + id.name + "' must be declared in an enclosing class");
			}
		}
	};
	pp$8.parseExportAllDeclaration = function(node, exports$1) {
		if (this.options.ecmaVersion >= 11) {
			if (this.eatContextual("as")) {
				node.exported = this.parseModuleExportName();
				this.checkExport(exports$1, node.exported, this.lastTokStart);
			} else node.exported = null;
		}
		this.expectContextual("from");
		if (this.type !== types$1.string) this.unexpected();
		node.source = this.parseExprAtom();
		if (this.options.ecmaVersion >= 16) node.attributes = this.parseWithClause();
		this.semicolon();
		return this.finishNode(node, "ExportAllDeclaration");
	};
	pp$8.parseExport = function(node, exports$1) {
		this.next();
		if (this.eat(types$1.star)) return this.parseExportAllDeclaration(node, exports$1);
		if (this.eat(types$1._default)) {
			this.checkExport(exports$1, "default", this.lastTokStart);
			node.declaration = this.parseExportDefaultDeclaration();
			return this.finishNode(node, "ExportDefaultDeclaration");
		}
		if (this.shouldParseExportStatement()) {
			node.declaration = this.parseExportDeclaration(node);
			if (node.declaration.type === "VariableDeclaration") this.checkVariableExport(exports$1, node.declaration.declarations);
			else this.checkExport(exports$1, node.declaration.id, node.declaration.id.start);
			node.specifiers = [];
			node.source = null;
			if (this.options.ecmaVersion >= 16) node.attributes = [];
		} else {
			node.declaration = null;
			node.specifiers = this.parseExportSpecifiers(exports$1);
			if (this.eatContextual("from")) {
				if (this.type !== types$1.string) this.unexpected();
				node.source = this.parseExprAtom();
				if (this.options.ecmaVersion >= 16) node.attributes = this.parseWithClause();
			} else {
				for (var i = 0, list = node.specifiers; i < list.length; i += 1) {
					var spec = list[i];
					this.checkUnreserved(spec.local);
					this.checkLocalExport(spec.local);
					if (spec.local.type === "Literal") this.raise(spec.local.start, "A string literal cannot be used as an exported binding without `from`.");
				}
				node.source = null;
				if (this.options.ecmaVersion >= 16) node.attributes = [];
			}
			this.semicolon();
		}
		return this.finishNode(node, "ExportNamedDeclaration");
	};
	pp$8.parseExportDeclaration = function(node) {
		return this.parseStatement(null);
	};
	pp$8.parseExportDefaultDeclaration = function() {
		var isAsync;
		if (this.type === types$1._function || (isAsync = this.isAsyncFunction())) {
			var fNode = this.startNode();
			this.next();
			if (isAsync) this.next();
			return this.parseFunction(fNode, FUNC_STATEMENT | FUNC_NULLABLE_ID, false, isAsync);
		} else if (this.type === types$1._class) {
			var cNode = this.startNode();
			return this.parseClass(cNode, "nullableID");
		} else {
			var declaration = this.parseMaybeAssign();
			this.semicolon();
			return declaration;
		}
	};
	pp$8.checkExport = function(exports$1, name, pos) {
		if (!exports$1) return;
		if (typeof name !== "string") name = name.type === "Identifier" ? name.name : name.value;
		if (hasOwn(exports$1, name)) this.raiseRecoverable(pos, "Duplicate export '" + name + "'");
		exports$1[name] = true;
	};
	pp$8.checkPatternExport = function(exports$1, pat) {
		var type = pat.type;
		if (type === "Identifier") this.checkExport(exports$1, pat, pat.start);
		else if (type === "ObjectPattern") for (var i = 0, list = pat.properties; i < list.length; i += 1) {
			var prop = list[i];
			this.checkPatternExport(exports$1, prop);
		}
		else if (type === "ArrayPattern") for (var i$1 = 0, list$1 = pat.elements; i$1 < list$1.length; i$1 += 1) {
			var elt = list$1[i$1];
			if (elt) this.checkPatternExport(exports$1, elt);
		}
		else if (type === "Property") this.checkPatternExport(exports$1, pat.value);
		else if (type === "AssignmentPattern") this.checkPatternExport(exports$1, pat.left);
		else if (type === "RestElement") this.checkPatternExport(exports$1, pat.argument);
	};
	pp$8.checkVariableExport = function(exports$1, decls) {
		if (!exports$1) return;
		for (var i = 0, list = decls; i < list.length; i += 1) {
			var decl = list[i];
			this.checkPatternExport(exports$1, decl.id);
		}
	};
	pp$8.shouldParseExportStatement = function() {
		return this.type.keyword === "var" || this.type.keyword === "const" || this.type.keyword === "class" || this.type.keyword === "function" || this.isLet() || this.isAsyncFunction();
	};
	pp$8.parseExportSpecifier = function(exports$1) {
		var node = this.startNode();
		node.local = this.parseModuleExportName();
		node.exported = this.eatContextual("as") ? this.parseModuleExportName() : node.local;
		this.checkExport(exports$1, node.exported, node.exported.start);
		return this.finishNode(node, "ExportSpecifier");
	};
	pp$8.parseExportSpecifiers = function(exports$1) {
		var nodes = [], first = true;
		this.expect(types$1.braceL);
		while (!this.eat(types$1.braceR)) {
			if (!first) {
				this.expect(types$1.comma);
				if (this.afterTrailingComma(types$1.braceR)) break;
			} else first = false;
			nodes.push(this.parseExportSpecifier(exports$1));
		}
		return nodes;
	};
	pp$8.parseImport = function(node) {
		this.next();
		if (this.type === types$1.string) {
			node.specifiers = empty$1;
			node.source = this.parseExprAtom();
		} else {
			node.specifiers = this.parseImportSpecifiers();
			this.expectContextual("from");
			node.source = this.type === types$1.string ? this.parseExprAtom() : this.unexpected();
		}
		if (this.options.ecmaVersion >= 16) node.attributes = this.parseWithClause();
		this.semicolon();
		return this.finishNode(node, "ImportDeclaration");
	};
	pp$8.parseImportSpecifier = function() {
		var node = this.startNode();
		node.imported = this.parseModuleExportName();
		if (this.eatContextual("as")) node.local = this.parseIdent();
		else {
			this.checkUnreserved(node.imported);
			node.local = node.imported;
		}
		this.checkLValSimple(node.local, BIND_LEXICAL);
		return this.finishNode(node, "ImportSpecifier");
	};
	pp$8.parseImportDefaultSpecifier = function() {
		var node = this.startNode();
		node.local = this.parseIdent();
		this.checkLValSimple(node.local, BIND_LEXICAL);
		return this.finishNode(node, "ImportDefaultSpecifier");
	};
	pp$8.parseImportNamespaceSpecifier = function() {
		var node = this.startNode();
		this.next();
		this.expectContextual("as");
		node.local = this.parseIdent();
		this.checkLValSimple(node.local, BIND_LEXICAL);
		return this.finishNode(node, "ImportNamespaceSpecifier");
	};
	pp$8.parseImportSpecifiers = function() {
		var nodes = [], first = true;
		if (this.type === types$1.name) {
			nodes.push(this.parseImportDefaultSpecifier());
			if (!this.eat(types$1.comma)) return nodes;
		}
		if (this.type === types$1.star) {
			nodes.push(this.parseImportNamespaceSpecifier());
			return nodes;
		}
		this.expect(types$1.braceL);
		while (!this.eat(types$1.braceR)) {
			if (!first) {
				this.expect(types$1.comma);
				if (this.afterTrailingComma(types$1.braceR)) break;
			} else first = false;
			nodes.push(this.parseImportSpecifier());
		}
		return nodes;
	};
	pp$8.parseWithClause = function() {
		var nodes = [];
		if (!this.eat(types$1._with)) return nodes;
		this.expect(types$1.braceL);
		var attributeKeys = {};
		var first = true;
		while (!this.eat(types$1.braceR)) {
			if (!first) {
				this.expect(types$1.comma);
				if (this.afterTrailingComma(types$1.braceR)) break;
			} else first = false;
			var attr = this.parseImportAttribute();
			var keyName = attr.key.type === "Identifier" ? attr.key.name : attr.key.value;
			if (hasOwn(attributeKeys, keyName)) this.raiseRecoverable(attr.key.start, "Duplicate attribute key '" + keyName + "'");
			attributeKeys[keyName] = true;
			nodes.push(attr);
		}
		return nodes;
	};
	pp$8.parseImportAttribute = function() {
		var node = this.startNode();
		node.key = this.type === types$1.string ? this.parseExprAtom() : this.parseIdent(this.options.allowReserved !== "never");
		this.expect(types$1.colon);
		if (this.type !== types$1.string) this.unexpected();
		node.value = this.parseExprAtom();
		return this.finishNode(node, "ImportAttribute");
	};
	pp$8.parseModuleExportName = function() {
		if (this.options.ecmaVersion >= 13 && this.type === types$1.string) {
			var stringLiteral = this.parseLiteral(this.value);
			if (loneSurrogate.test(stringLiteral.value)) this.raise(stringLiteral.start, "An export name cannot include a lone surrogate.");
			return stringLiteral;
		}
		return this.parseIdent(true);
	};
	pp$8.adaptDirectivePrologue = function(statements) {
		for (var i = 0; i < statements.length && this.isDirectiveCandidate(statements[i]); ++i) statements[i].directive = statements[i].expression.raw.slice(1, -1);
	};
	pp$8.isDirectiveCandidate = function(statement) {
		return this.options.ecmaVersion >= 5 && statement.type === "ExpressionStatement" && statement.expression.type === "Literal" && typeof statement.expression.value === "string" && (this.input[statement.start] === "\"" || this.input[statement.start] === "'");
	};
	pp$7 = Parser.prototype;
	pp$7.toAssignable = function(node, isBinding, refDestructuringErrors) {
		if (this.options.ecmaVersion >= 6 && node) switch (node.type) {
			case "Identifier":
				if (this.inAsync && node.name === "await") this.raise(node.start, "Cannot use 'await' as identifier inside an async function");
				break;
			case "ObjectPattern":
			case "ArrayPattern":
			case "AssignmentPattern":
			case "RestElement": break;
			case "ObjectExpression":
				node.type = "ObjectPattern";
				if (refDestructuringErrors) this.checkPatternErrors(refDestructuringErrors, true);
				for (var i = 0, list = node.properties; i < list.length; i += 1) {
					var prop = list[i];
					this.toAssignable(prop, isBinding);
					if (prop.type === "RestElement" && (prop.argument.type === "ArrayPattern" || prop.argument.type === "ObjectPattern")) this.raise(prop.argument.start, "Unexpected token");
				}
				break;
			case "Property":
				if (node.kind !== "init") this.raise(node.key.start, "Object pattern can't contain getter or setter");
				this.toAssignable(node.value, isBinding);
				break;
			case "ArrayExpression":
				node.type = "ArrayPattern";
				if (refDestructuringErrors) this.checkPatternErrors(refDestructuringErrors, true);
				this.toAssignableList(node.elements, isBinding);
				break;
			case "SpreadElement":
				node.type = "RestElement";
				this.toAssignable(node.argument, isBinding);
				if (node.argument.type === "AssignmentPattern") this.raise(node.argument.start, "Rest elements cannot have a default value");
				break;
			case "AssignmentExpression":
				if (node.operator !== "=") this.raise(node.left.end, "Only '=' operator can be used for specifying default value.");
				node.type = "AssignmentPattern";
				delete node.operator;
				this.toAssignable(node.left, isBinding);
				break;
			case "ParenthesizedExpression":
				this.toAssignable(node.expression, isBinding, refDestructuringErrors);
				break;
			case "ChainExpression":
				this.raiseRecoverable(node.start, "Optional chaining cannot appear in left-hand side");
				break;
			case "MemberExpression": if (!isBinding) break;
			default: this.raise(node.start, "Assigning to rvalue");
		}
		else if (refDestructuringErrors) this.checkPatternErrors(refDestructuringErrors, true);
		return node;
	};
	pp$7.toAssignableList = function(exprList, isBinding) {
		var end = exprList.length;
		for (var i = 0; i < end; i++) {
			var elt = exprList[i];
			if (elt) this.toAssignable(elt, isBinding);
		}
		if (end) {
			var last = exprList[end - 1];
			if (this.options.ecmaVersion === 6 && isBinding && last && last.type === "RestElement" && last.argument.type !== "Identifier") this.unexpected(last.argument.start);
		}
		return exprList;
	};
	pp$7.parseSpread = function(refDestructuringErrors) {
		var node = this.startNode();
		this.next();
		node.argument = this.parseMaybeAssign(false, refDestructuringErrors);
		return this.finishNode(node, "SpreadElement");
	};
	pp$7.parseRestBinding = function() {
		var node = this.startNode();
		this.next();
		if (this.options.ecmaVersion === 6 && this.type !== types$1.name) this.unexpected();
		node.argument = this.parseBindingAtom();
		return this.finishNode(node, "RestElement");
	};
	pp$7.parseBindingAtom = function() {
		if (this.options.ecmaVersion >= 6) switch (this.type) {
			case types$1.bracketL:
				var node = this.startNode();
				this.next();
				node.elements = this.parseBindingList(types$1.bracketR, true, true);
				return this.finishNode(node, "ArrayPattern");
			case types$1.braceL: return this.parseObj(true);
		}
		return this.parseIdent();
	};
	pp$7.parseBindingList = function(close, allowEmpty, allowTrailingComma, allowModifiers) {
		var elts = [], first = true;
		while (!this.eat(close)) {
			if (first) first = false;
			else this.expect(types$1.comma);
			if (allowEmpty && this.type === types$1.comma) elts.push(null);
			else if (allowTrailingComma && this.afterTrailingComma(close)) break;
			else if (this.type === types$1.ellipsis) {
				var rest = this.parseRestBinding();
				this.parseBindingListItem(rest);
				elts.push(rest);
				if (this.type === types$1.comma) this.raiseRecoverable(this.start, "Comma is not permitted after the rest element");
				this.expect(close);
				break;
			} else elts.push(this.parseAssignableListItem(allowModifiers));
		}
		return elts;
	};
	pp$7.parseAssignableListItem = function(allowModifiers) {
		var elem = this.parseMaybeDefault(this.start, this.startLoc);
		this.parseBindingListItem(elem);
		return elem;
	};
	pp$7.parseBindingListItem = function(param) {
		return param;
	};
	pp$7.parseMaybeDefault = function(startPos, startLoc, left) {
		left = left || this.parseBindingAtom();
		if (this.options.ecmaVersion < 6 || !this.eat(types$1.eq)) return left;
		var node = this.startNodeAt(startPos, startLoc);
		node.left = left;
		node.right = this.parseMaybeAssign();
		return this.finishNode(node, "AssignmentPattern");
	};
	pp$7.checkLValSimple = function(expr, bindingType, checkClashes) {
		if (bindingType === void 0) bindingType = BIND_NONE;
		var isBind = bindingType !== BIND_NONE;
		switch (expr.type) {
			case "Identifier":
				if (this.strict && this.reservedWordsStrictBind.test(expr.name)) this.raiseRecoverable(expr.start, (isBind ? "Binding " : "Assigning to ") + expr.name + " in strict mode");
				if (isBind) {
					if (bindingType === BIND_LEXICAL && expr.name === "let") this.raiseRecoverable(expr.start, "let is disallowed as a lexically bound name");
					if (checkClashes) {
						if (hasOwn(checkClashes, expr.name)) this.raiseRecoverable(expr.start, "Argument name clash");
						checkClashes[expr.name] = true;
					}
					if (bindingType !== BIND_OUTSIDE) this.declareName(expr.name, bindingType, expr.start);
				}
				break;
			case "ChainExpression":
				this.raiseRecoverable(expr.start, "Optional chaining cannot appear in left-hand side");
				break;
			case "MemberExpression":
				if (isBind) this.raiseRecoverable(expr.start, "Binding member expression");
				break;
			case "ParenthesizedExpression":
				if (isBind) this.raiseRecoverable(expr.start, "Binding parenthesized expression");
				return this.checkLValSimple(expr.expression, bindingType, checkClashes);
			default: this.raise(expr.start, (isBind ? "Binding" : "Assigning to") + " rvalue");
		}
	};
	pp$7.checkLValPattern = function(expr, bindingType, checkClashes) {
		if (bindingType === void 0) bindingType = BIND_NONE;
		switch (expr.type) {
			case "ObjectPattern":
				for (var i = 0, list = expr.properties; i < list.length; i += 1) {
					var prop = list[i];
					this.checkLValInnerPattern(prop, bindingType, checkClashes);
				}
				break;
			case "ArrayPattern":
				for (var i$1 = 0, list$1 = expr.elements; i$1 < list$1.length; i$1 += 1) {
					var elem = list$1[i$1];
					if (elem) this.checkLValInnerPattern(elem, bindingType, checkClashes);
				}
				break;
			default: this.checkLValSimple(expr, bindingType, checkClashes);
		}
	};
	pp$7.checkLValInnerPattern = function(expr, bindingType, checkClashes) {
		if (bindingType === void 0) bindingType = BIND_NONE;
		switch (expr.type) {
			case "Property":
				this.checkLValInnerPattern(expr.value, bindingType, checkClashes);
				break;
			case "AssignmentPattern":
				this.checkLValPattern(expr.left, bindingType, checkClashes);
				break;
			case "RestElement":
				this.checkLValPattern(expr.argument, bindingType, checkClashes);
				break;
			default: this.checkLValPattern(expr, bindingType, checkClashes);
		}
	};
	TokContext = function TokContext(token, isExpr, preserveSpace, override, generator) {
		this.token = token;
		this.isExpr = !!isExpr;
		this.preserveSpace = !!preserveSpace;
		this.override = override;
		this.generator = !!generator;
	};
	types = {
		b_stat: new TokContext("{", false),
		b_expr: new TokContext("{", true),
		b_tmpl: new TokContext("${", false),
		p_stat: new TokContext("(", false),
		p_expr: new TokContext("(", true),
		q_tmpl: new TokContext("`", true, true, function(p) {
			return p.tryReadTemplateToken();
		}),
		f_stat: new TokContext("function", false),
		f_expr: new TokContext("function", true),
		f_expr_gen: new TokContext("function", true, false, null, true),
		f_gen: new TokContext("function", false, false, null, true)
	};
	pp$6 = Parser.prototype;
	pp$6.initialContext = function() {
		return [types.b_stat];
	};
	pp$6.curContext = function() {
		return this.context[this.context.length - 1];
	};
	pp$6.braceIsBlock = function(prevType) {
		var parent = this.curContext();
		if (parent === types.f_expr || parent === types.f_stat) return true;
		if (prevType === types$1.colon && (parent === types.b_stat || parent === types.b_expr)) return !parent.isExpr;
		if (prevType === types$1._return || prevType === types$1.name && this.exprAllowed) return lineBreak.test(this.input.slice(this.lastTokEnd, this.start));
		if (prevType === types$1._else || prevType === types$1.semi || prevType === types$1.eof || prevType === types$1.parenR || prevType === types$1.arrow) return true;
		if (prevType === types$1.braceL) return parent === types.b_stat;
		if (prevType === types$1._var || prevType === types$1._const || prevType === types$1.name) return false;
		return !this.exprAllowed;
	};
	pp$6.inGeneratorContext = function() {
		for (var i = this.context.length - 1; i >= 1; i--) {
			var context = this.context[i];
			if (context.token === "function") return context.generator;
		}
		return false;
	};
	pp$6.updateContext = function(prevType) {
		var update, type = this.type;
		if (type.keyword && prevType === types$1.dot) this.exprAllowed = false;
		else if (update = type.updateContext) update.call(this, prevType);
		else this.exprAllowed = type.beforeExpr;
	};
	pp$6.overrideContext = function(tokenCtx) {
		if (this.curContext() !== tokenCtx) this.context[this.context.length - 1] = tokenCtx;
	};
	types$1.parenR.updateContext = types$1.braceR.updateContext = function() {
		if (this.context.length === 1) {
			this.exprAllowed = true;
			return;
		}
		var out = this.context.pop();
		if (out === types.b_stat && this.curContext().token === "function") out = this.context.pop();
		this.exprAllowed = !out.isExpr;
	};
	types$1.braceL.updateContext = function(prevType) {
		this.context.push(this.braceIsBlock(prevType) ? types.b_stat : types.b_expr);
		this.exprAllowed = true;
	};
	types$1.dollarBraceL.updateContext = function() {
		this.context.push(types.b_tmpl);
		this.exprAllowed = true;
	};
	types$1.parenL.updateContext = function(prevType) {
		var statementParens = prevType === types$1._if || prevType === types$1._for || prevType === types$1._with || prevType === types$1._while;
		this.context.push(statementParens ? types.p_stat : types.p_expr);
		this.exprAllowed = true;
	};
	types$1.incDec.updateContext = function() {};
	types$1._function.updateContext = types$1._class.updateContext = function(prevType) {
		if (prevType.beforeExpr && prevType !== types$1._else && !(prevType === types$1.semi && this.curContext() !== types.p_stat) && !(prevType === types$1._return && lineBreak.test(this.input.slice(this.lastTokEnd, this.start))) && !((prevType === types$1.colon || prevType === types$1.braceL) && this.curContext() === types.b_stat)) this.context.push(types.f_expr);
		else this.context.push(types.f_stat);
		this.exprAllowed = false;
	};
	types$1.colon.updateContext = function() {
		if (this.curContext().token === "function") this.context.pop();
		this.exprAllowed = true;
	};
	types$1.backQuote.updateContext = function() {
		if (this.curContext() === types.q_tmpl) this.context.pop();
		else this.context.push(types.q_tmpl);
		this.exprAllowed = false;
	};
	types$1.star.updateContext = function(prevType) {
		if (prevType === types$1._function) {
			var index = this.context.length - 1;
			if (this.context[index] === types.f_expr) this.context[index] = types.f_expr_gen;
			else this.context[index] = types.f_gen;
		}
		this.exprAllowed = true;
	};
	types$1.name.updateContext = function(prevType) {
		var allowed = false;
		if (this.options.ecmaVersion >= 6 && prevType !== types$1.dot) {
			if (this.value === "of" && !this.exprAllowed || this.value === "yield" && this.inGeneratorContext()) allowed = true;
		}
		this.exprAllowed = allowed;
	};
	pp$5 = Parser.prototype;
	pp$5.checkPropClash = function(prop, propHash, refDestructuringErrors) {
		if (this.options.ecmaVersion >= 9 && prop.type === "SpreadElement") return;
		if (this.options.ecmaVersion >= 6 && (prop.computed || prop.method || prop.shorthand)) return;
		var key = prop.key;
		var name;
		switch (key.type) {
			case "Identifier":
				name = key.name;
				break;
			case "Literal":
				name = String(key.value);
				break;
			default: return;
		}
		var kind = prop.kind;
		if (this.options.ecmaVersion >= 6) {
			if (name === "__proto__" && kind === "init") {
				if (propHash.proto) {
					if (refDestructuringErrors) {
						if (refDestructuringErrors.doubleProto < 0) refDestructuringErrors.doubleProto = key.start;
					} else this.raiseRecoverable(key.start, "Redefinition of __proto__ property");
				}
				propHash.proto = true;
			}
			return;
		}
		name = "$" + name;
		var other = propHash[name];
		if (other) {
			var redefinition;
			if (kind === "init") redefinition = this.strict && other.init || other.get || other.set;
			else redefinition = other.init || other[kind];
			if (redefinition) this.raiseRecoverable(key.start, "Redefinition of property");
		} else other = propHash[name] = {
			init: false,
			get: false,
			set: false
		};
		other[kind] = true;
	};
	pp$5.parseExpression = function(forInit, refDestructuringErrors) {
		var this$1$1 = this;
		return this.catchStackOverflow(function() {
			var startPos = this$1$1.start, startLoc = this$1$1.startLoc;
			var expr = this$1$1.parseMaybeAssign(forInit, refDestructuringErrors);
			if (this$1$1.type === types$1.comma) {
				var node = this$1$1.startNodeAt(startPos, startLoc);
				node.expressions = [expr];
				while (this$1$1.eat(types$1.comma)) node.expressions.push(this$1$1.parseMaybeAssign(forInit, refDestructuringErrors));
				return this$1$1.finishNode(node, "SequenceExpression");
			}
			return expr;
		});
	};
	pp$5.parseMaybeAssign = function(forInit, refDestructuringErrors, afterLeftParse) {
		if (this.isContextual("yield")) {
			if (this.inGenerator) return this.parseYield(forInit);
			else this.exprAllowed = false;
		}
		var ownDestructuringErrors = false, oldParenAssign = -1, oldTrailingComma = -1, oldDoubleProto = -1;
		if (refDestructuringErrors) {
			oldParenAssign = refDestructuringErrors.parenthesizedAssign;
			oldTrailingComma = refDestructuringErrors.trailingComma;
			oldDoubleProto = refDestructuringErrors.doubleProto;
			refDestructuringErrors.parenthesizedAssign = refDestructuringErrors.trailingComma = -1;
		} else {
			refDestructuringErrors = new DestructuringErrors();
			ownDestructuringErrors = true;
		}
		var startPos = this.start, startLoc = this.startLoc;
		if (this.type === types$1.parenL || this.type === types$1.name) {
			this.potentialArrowAt = this.start;
			this.potentialArrowInForAwait = forInit === "await";
		}
		var left = this.parseMaybeConditional(forInit, refDestructuringErrors);
		if (afterLeftParse) left = afterLeftParse.call(this, left, startPos, startLoc);
		if (this.type.isAssign) {
			var node = this.startNodeAt(startPos, startLoc);
			node.operator = this.value;
			if (this.type === types$1.eq) left = this.toAssignable(left, false, refDestructuringErrors);
			if (!ownDestructuringErrors) {
				refDestructuringErrors.parenthesizedAssign = refDestructuringErrors.trailingComma = -1;
				if (refDestructuringErrors.shorthandAssign >= left.start) refDestructuringErrors.shorthandAssign = -1;
				if (refDestructuringErrors.doubleProto >= left.start) refDestructuringErrors.doubleProto = -1;
			}
			if (this.type === types$1.eq) this.checkLValPattern(left);
			else this.checkLValSimple(left);
			node.left = left;
			this.next();
			node.right = this.parseMaybeAssign(forInit);
			if (oldDoubleProto > -1) refDestructuringErrors.doubleProto = oldDoubleProto;
			return this.finishNode(node, "AssignmentExpression");
		} else if (ownDestructuringErrors) this.checkExpressionErrors(refDestructuringErrors, true);
		if (oldParenAssign > -1) refDestructuringErrors.parenthesizedAssign = oldParenAssign;
		if (oldTrailingComma > -1) refDestructuringErrors.trailingComma = oldTrailingComma;
		return left;
	};
	pp$5.parseMaybeConditional = function(forInit, refDestructuringErrors) {
		var startPos = this.start, startLoc = this.startLoc;
		var expr = this.parseExprOps(forInit, refDestructuringErrors);
		if (this.checkExpressionErrors(refDestructuringErrors)) return expr;
		if (!(expr.type === "ArrowFunctionExpression" && expr.start === startPos) && this.eat(types$1.question)) {
			var node = this.startNodeAt(startPos, startLoc);
			node.test = expr;
			node.consequent = this.parseMaybeAssign();
			this.expect(types$1.colon);
			node.alternate = this.parseMaybeAssign(forInit);
			return this.finishNode(node, "ConditionalExpression");
		}
		return expr;
	};
	pp$5.parseExprOps = function(forInit, refDestructuringErrors) {
		var startPos = this.start, startLoc = this.startLoc;
		var expr = this.parseMaybeUnary(refDestructuringErrors, false, false, forInit);
		if (this.checkExpressionErrors(refDestructuringErrors)) return expr;
		return expr.start === startPos && expr.type === "ArrowFunctionExpression" ? expr : this.parseExprOp(expr, startPos, startLoc, -1, forInit);
	};
	pp$5.parseExprOp = function(left, leftStartPos, leftStartLoc, minPrec, forInit) {
		var prec = this.type.binop;
		if (prec != null && (!forInit || this.type !== types$1._in)) {
			if (prec > minPrec) {
				var logical = this.type === types$1.logicalOR || this.type === types$1.logicalAND;
				var coalesce = this.type === types$1.coalesce;
				if (coalesce) prec = types$1.logicalAND.binop;
				var op = this.value;
				this.next();
				var startPos = this.start, startLoc = this.startLoc;
				var right = this.parseExprOp(this.parseMaybeUnary(null, false, false, forInit), startPos, startLoc, prec, forInit);
				var node = this.buildBinary(leftStartPos, leftStartLoc, left, right, op, logical || coalesce);
				if (logical && this.type === types$1.coalesce || coalesce && (this.type === types$1.logicalOR || this.type === types$1.logicalAND)) this.raiseRecoverable(this.start, "Logical expressions and coalesce expressions cannot be mixed. Wrap either by parentheses");
				return this.parseExprOp(node, leftStartPos, leftStartLoc, minPrec, forInit);
			}
		}
		return left;
	};
	pp$5.buildBinary = function(startPos, startLoc, left, right, op, logical) {
		if (right.type === "PrivateIdentifier") this.raise(right.start, "Private identifier can only be left side of binary expression");
		var node = this.startNodeAt(startPos, startLoc);
		node.left = left;
		node.operator = op;
		node.right = right;
		return this.finishNode(node, logical ? "LogicalExpression" : "BinaryExpression");
	};
	pp$5.parseMaybeUnary = function(refDestructuringErrors, sawUnary, incDec, forInit) {
		var startPos = this.start, startLoc = this.startLoc, expr;
		if (this.isContextual("await") && this.canAwait) {
			expr = this.parseAwait(forInit);
			sawUnary = true;
		} else if (this.type.prefix) {
			var node = this.startNode(), update = this.type === types$1.incDec;
			node.operator = this.value;
			node.prefix = true;
			this.next();
			node.argument = this.parseMaybeUnary(null, true, update, forInit);
			this.checkExpressionErrors(refDestructuringErrors, true);
			if (update) this.checkLValSimple(node.argument);
			else if (this.strict && node.operator === "delete" && isLocalVariableAccess(node.argument)) this.raiseRecoverable(node.start, "Deleting local variable in strict mode");
			else if (node.operator === "delete" && isPrivateFieldAccess(node.argument)) this.raiseRecoverable(node.start, "Private fields can not be deleted");
			else sawUnary = true;
			expr = this.finishNode(node, update ? "UpdateExpression" : "UnaryExpression");
		} else if (!sawUnary && this.type === types$1.privateId) {
			if ((forInit || this.privateNameStack.length === 0) && this.options.checkPrivateFields) this.unexpected();
			expr = this.parsePrivateIdent();
			if (this.type !== types$1._in) this.unexpected();
		} else {
			expr = this.parseExprSubscripts(refDestructuringErrors, forInit);
			if (this.checkExpressionErrors(refDestructuringErrors)) return expr;
			while (this.type.postfix && !this.canInsertSemicolon()) {
				var node$1 = this.startNodeAt(startPos, startLoc);
				node$1.operator = this.value;
				node$1.prefix = false;
				node$1.argument = expr;
				this.checkLValSimple(expr);
				this.next();
				expr = this.finishNode(node$1, "UpdateExpression");
			}
		}
		if (!incDec && !(expr.type === "ArrowFunctionExpression" && expr.start === startPos) && this.eat(types$1.starstar)) {
			if (sawUnary) this.unexpected(this.lastTokStart);
			else return this.buildBinary(startPos, startLoc, expr, this.parseMaybeUnary(null, false, false, forInit), "**", false);
		} else return expr;
	};
	pp$5.parseExprSubscripts = function(refDestructuringErrors, forInit) {
		var startPos = this.start, startLoc = this.startLoc;
		var oldDoubleProto = -1, oldShorthandAssign = -1;
		if (refDestructuringErrors) {
			oldDoubleProto = refDestructuringErrors.doubleProto;
			oldShorthandAssign = refDestructuringErrors.shorthandAssign;
			refDestructuringErrors.doubleProto = refDestructuringErrors.shorthandAssign = -1;
		}
		var expr = this.parseExprAtom(refDestructuringErrors, forInit);
		if (expr.type === "ArrowFunctionExpression" && this.input.slice(this.lastTokStart, this.lastTokEnd) !== ")") return expr;
		var result = this.parseSubscripts(expr, startPos, startLoc, false, forInit);
		if (refDestructuringErrors) {
			if (result.end > expr.end) {
				this.checkExpressionErrors(refDestructuringErrors, true);
				if (refDestructuringErrors.parenthesizedAssign >= result.start) refDestructuringErrors.parenthesizedAssign = -1;
				if (refDestructuringErrors.parenthesizedBind >= result.start) refDestructuringErrors.parenthesizedBind = -1;
				if (refDestructuringErrors.trailingComma >= result.start) refDestructuringErrors.trailingComma = -1;
			}
			if (oldDoubleProto > -1) refDestructuringErrors.doubleProto = oldDoubleProto;
			if (oldShorthandAssign > -1) refDestructuringErrors.shorthandAssign = oldShorthandAssign;
		}
		return result;
	};
	pp$5.parseSubscripts = function(base, startPos, startLoc, noCalls, forInit) {
		var maybeAsyncArrow = this.options.ecmaVersion >= 8 && base.type === "Identifier" && base.name === "async" && this.lastTokEnd === base.end && !this.canInsertSemicolon() && base.end - base.start === 5 && this.potentialArrowAt === base.start;
		var optionalChained = false;
		while (true) {
			var element = this.parseSubscript(base, startPos, startLoc, noCalls, maybeAsyncArrow, optionalChained, forInit);
			if (element.optional) optionalChained = true;
			if (element.end === base.end || element.type === "ArrowFunctionExpression") {
				if (optionalChained) {
					var chainNode = this.startNodeAt(startPos, startLoc);
					chainNode.expression = element;
					element = this.finishNode(chainNode, "ChainExpression");
				}
				return element;
			}
			base = element;
			maybeAsyncArrow = false;
		}
	};
	pp$5.shouldParseAsyncArrow = function() {
		return !this.canInsertSemicolon() && this.eat(types$1.arrow);
	};
	pp$5.parseSubscriptAsyncArrow = function(startPos, startLoc, exprList, forInit) {
		return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), exprList, true, forInit);
	};
	pp$5.parseSubscript = function(base, startPos, startLoc, noCalls, maybeAsyncArrow, optionalChained, forInit) {
		var optionalSupported = this.options.ecmaVersion >= 11;
		var optional = optionalSupported && this.eat(types$1.questionDot);
		if (noCalls && optional) this.raise(this.lastTokStart, "Optional chaining cannot appear in the callee of new expressions");
		var computed = this.eat(types$1.bracketL);
		if (computed || optional && this.type !== types$1.parenL && this.type !== types$1.backQuote || this.eat(types$1.dot)) {
			var node = this.startNodeAt(startPos, startLoc);
			node.object = base;
			if (computed) {
				node.property = this.parseExpression();
				this.expect(types$1.bracketR);
			} else if (this.type === types$1.privateId && base.type !== "Super") node.property = this.parsePrivateIdent();
			else node.property = this.parseIdent(this.options.allowReserved !== "never");
			node.computed = !!computed;
			if (optionalSupported) node.optional = optional;
			base = this.finishNode(node, "MemberExpression");
		} else if (!noCalls && this.eat(types$1.parenL)) {
			var refDestructuringErrors = new DestructuringErrors(), oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;
			this.yieldPos = 0;
			this.awaitPos = 0;
			this.awaitIdentPos = 0;
			var exprList = this.parseExprList(types$1.parenR, this.options.ecmaVersion >= 8, false, refDestructuringErrors);
			if (maybeAsyncArrow && !optional && this.shouldParseAsyncArrow()) {
				this.checkPatternErrors(refDestructuringErrors, false);
				this.checkYieldAwaitInDefaultParams();
				if (this.awaitIdentPos > 0) this.raise(this.awaitIdentPos, "Cannot use 'await' as identifier inside an async function");
				this.yieldPos = oldYieldPos;
				this.awaitPos = oldAwaitPos;
				this.awaitIdentPos = oldAwaitIdentPos;
				return this.parseSubscriptAsyncArrow(startPos, startLoc, exprList, forInit);
			}
			this.checkExpressionErrors(refDestructuringErrors, true);
			this.yieldPos = oldYieldPos || this.yieldPos;
			this.awaitPos = oldAwaitPos || this.awaitPos;
			this.awaitIdentPos = oldAwaitIdentPos || this.awaitIdentPos;
			var node$1 = this.startNodeAt(startPos, startLoc);
			node$1.callee = base;
			node$1.arguments = exprList;
			if (optionalSupported) node$1.optional = optional;
			base = this.finishNode(node$1, "CallExpression");
		} else if (this.type === types$1.backQuote) {
			if (optional || optionalChained) this.raise(this.start, "Optional chaining cannot appear in the tag of tagged template expressions");
			var node$2 = this.startNodeAt(startPos, startLoc);
			node$2.tag = base;
			node$2.quasi = this.parseTemplate({ isTagged: true });
			base = this.finishNode(node$2, "TaggedTemplateExpression");
		}
		return base;
	};
	pp$5.parseExprAtom = function(refDestructuringErrors, forInit, forNew) {
		if (this.type === types$1.slash) this.readRegexp();
		var node, canBeArrow = this.potentialArrowAt === this.start;
		switch (this.type) {
			case types$1._super:
				if (!this.allowSuper) this.raise(this.start, "'super' keyword outside a method");
				node = this.startNode();
				this.next();
				if (this.type === types$1.parenL && !this.allowDirectSuper) this.raise(node.start, "super() call outside constructor of a subclass");
				if (this.type !== types$1.dot && this.type !== types$1.bracketL && this.type !== types$1.parenL) this.unexpected();
				return this.finishNode(node, "Super");
			case types$1._this:
				node = this.startNode();
				this.next();
				return this.finishNode(node, "ThisExpression");
			case types$1.name:
				var startPos = this.start, startLoc = this.startLoc, containsEsc = this.containsEsc;
				var id = this.parseIdent(false);
				if (this.options.ecmaVersion >= 8 && !containsEsc && id.name === "async" && !this.canInsertSemicolon() && this.eat(types$1._function)) {
					this.overrideContext(types.f_expr);
					return this.parseFunction(this.startNodeAt(startPos, startLoc), 0, false, true, forInit);
				}
				if (canBeArrow && !this.canInsertSemicolon()) {
					if (this.eat(types$1.arrow)) return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), [id], false, forInit);
					if (this.options.ecmaVersion >= 8 && id.name === "async" && this.type === types$1.name && !containsEsc && (!this.potentialArrowInForAwait || this.value !== "of" || this.containsEsc)) {
						id = this.parseIdent(false);
						if (this.canInsertSemicolon() || !this.eat(types$1.arrow)) this.unexpected();
						return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), [id], true, forInit);
					}
				}
				return id;
			case types$1.regexp:
				var value = this.value;
				node = this.parseLiteral(value.value);
				node.regex = {
					pattern: value.pattern,
					flags: value.flags
				};
				return node;
			case types$1.num:
			case types$1.string: return this.parseLiteral(this.value);
			case types$1._null:
			case types$1._true:
			case types$1._false:
				node = this.startNode();
				node.value = this.type === types$1._null ? null : this.type === types$1._true;
				node.raw = this.type.keyword;
				this.next();
				return this.finishNode(node, "Literal");
			case types$1.parenL:
				var start = this.start, expr = this.parseParenAndDistinguishExpression(canBeArrow, forInit);
				if (refDestructuringErrors) {
					if (refDestructuringErrors.parenthesizedAssign < 0 && !this.isSimpleAssignTarget(expr)) refDestructuringErrors.parenthesizedAssign = start;
					if (refDestructuringErrors.parenthesizedBind < 0) refDestructuringErrors.parenthesizedBind = start;
				}
				return expr;
			case types$1.bracketL:
				node = this.startNode();
				this.next();
				node.elements = this.parseExprList(types$1.bracketR, true, true, refDestructuringErrors);
				return this.finishNode(node, "ArrayExpression");
			case types$1.braceL:
				this.overrideContext(types.b_expr);
				return this.parseObj(false, refDestructuringErrors);
			case types$1._function:
				node = this.startNode();
				this.next();
				return this.parseFunction(node, 0);
			case types$1._class: return this.parseClass(this.startNode(), false);
			case types$1._new: return this.parseNew();
			case types$1.backQuote: return this.parseTemplate();
			case types$1._import: if (this.options.ecmaVersion >= 11) return this.parseExprImport(forNew);
			else return this.unexpected();
			default: return this.parseExprAtomDefault();
		}
	};
	pp$5.parseExprAtomDefault = function() {
		this.unexpected();
	};
	pp$5.parseExprImport = function(forNew) {
		var node = this.startNode();
		if (this.containsEsc) this.raiseRecoverable(this.start, "Escape sequence in keyword import");
		this.next();
		if (this.type === types$1.parenL && !forNew) return this.parseDynamicImport(node);
		else if (this.type === types$1.dot) {
			var meta = this.startNodeAt(node.start, node.loc && node.loc.start);
			meta.name = "import";
			node.meta = this.finishNode(meta, "Identifier");
			return this.parseImportMeta(node);
		} else this.unexpected();
	};
	pp$5.parseDynamicImport = function(node) {
		this.next();
		node.source = this.parseMaybeAssign();
		if (this.options.ecmaVersion >= 16) {
			if (!this.eat(types$1.parenR)) {
				this.expect(types$1.comma);
				if (!this.afterTrailingComma(types$1.parenR)) {
					node.options = this.parseMaybeAssign();
					if (!this.eat(types$1.parenR)) {
						this.expect(types$1.comma);
						if (!this.afterTrailingComma(types$1.parenR)) this.unexpected();
					}
				} else node.options = null;
			} else node.options = null;
		} else if (!this.eat(types$1.parenR)) {
			var errorPos = this.start;
			if (this.eat(types$1.comma) && this.eat(types$1.parenR)) this.raiseRecoverable(errorPos, "Trailing comma is not allowed in import()");
			else this.unexpected(errorPos);
		}
		return this.finishNode(node, "ImportExpression");
	};
	pp$5.parseImportMeta = function(node) {
		this.next();
		var containsEsc = this.containsEsc;
		node.property = this.parseIdent(true);
		if (node.property.name !== "meta") this.raiseRecoverable(node.property.start, "The only valid meta property for import is 'import.meta'");
		if (containsEsc) this.raiseRecoverable(node.start, "'import.meta' must not contain escaped characters");
		if (this.options.sourceType !== "module" && !this.options.allowImportExportEverywhere) this.raiseRecoverable(node.start, "Cannot use 'import.meta' outside a module");
		return this.finishNode(node, "MetaProperty");
	};
	pp$5.parseLiteral = function(value) {
		var node = this.startNode();
		node.value = value;
		node.raw = this.input.slice(this.start, this.end);
		if (node.raw.charCodeAt(node.raw.length - 1) === 110) node.bigint = node.value != null ? node.value.toString() : node.raw.slice(0, -1).replace(/_/g, "");
		this.next();
		return this.finishNode(node, "Literal");
	};
	pp$5.parseParenExpression = function() {
		this.expect(types$1.parenL);
		var val = this.parseExpression();
		this.expect(types$1.parenR);
		return val;
	};
	pp$5.shouldParseArrow = function(exprList) {
		return !this.canInsertSemicolon();
	};
	pp$5.parseParenAndDistinguishExpression = function(canBeArrow, forInit) {
		var startPos = this.start, startLoc = this.startLoc, val, allowTrailingComma = this.options.ecmaVersion >= 8;
		if (this.options.ecmaVersion >= 6) {
			this.next();
			var innerStartPos = this.start, innerStartLoc = this.startLoc;
			var exprList = [], first = true, lastIsComma = false;
			var refDestructuringErrors = new DestructuringErrors(), oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, spreadStart;
			this.yieldPos = 0;
			this.awaitPos = 0;
			while (this.type !== types$1.parenR) {
				first ? first = false : this.expect(types$1.comma);
				if (allowTrailingComma && this.afterTrailingComma(types$1.parenR, true)) {
					lastIsComma = true;
					break;
				} else if (this.type === types$1.ellipsis) {
					spreadStart = this.start;
					exprList.push(this.parseParenItem(this.parseRestBinding()));
					if (this.type === types$1.comma) this.raiseRecoverable(this.start, "Comma is not permitted after the rest element");
					break;
				} else exprList.push(this.parseMaybeAssign(false, refDestructuringErrors, this.parseParenItem));
			}
			var innerEndPos = this.lastTokEnd, innerEndLoc = this.lastTokEndLoc;
			this.expect(types$1.parenR);
			if (canBeArrow && this.shouldParseArrow(exprList) && this.eat(types$1.arrow)) {
				this.checkPatternErrors(refDestructuringErrors, false);
				this.checkYieldAwaitInDefaultParams();
				this.yieldPos = oldYieldPos;
				this.awaitPos = oldAwaitPos;
				return this.parseParenArrowList(startPos, startLoc, exprList, forInit);
			}
			if (!exprList.length || lastIsComma) this.unexpected(this.lastTokStart);
			if (spreadStart) this.unexpected(spreadStart);
			this.checkExpressionErrors(refDestructuringErrors, true);
			this.yieldPos = oldYieldPos || this.yieldPos;
			this.awaitPos = oldAwaitPos || this.awaitPos;
			if (exprList.length > 1) {
				val = this.startNodeAt(innerStartPos, innerStartLoc);
				val.expressions = exprList;
				this.finishNodeAt(val, "SequenceExpression", innerEndPos, innerEndLoc);
			} else val = exprList[0];
		} else val = this.parseParenExpression();
		if (this.options.preserveParens) {
			var par = this.startNodeAt(startPos, startLoc);
			par.expression = val;
			return this.finishNode(par, "ParenthesizedExpression");
		} else return val;
	};
	pp$5.parseParenItem = function(item) {
		return item;
	};
	pp$5.parseParenArrowList = function(startPos, startLoc, exprList, forInit) {
		return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), exprList, false, forInit);
	};
	empty$2 = [];
	pp$5.parseNew = function() {
		if (this.containsEsc) this.raiseRecoverable(this.start, "Escape sequence in keyword new");
		var node = this.startNode();
		this.next();
		if (this.options.ecmaVersion >= 6 && this.type === types$1.dot) {
			var meta = this.startNodeAt(node.start, node.loc && node.loc.start);
			meta.name = "new";
			node.meta = this.finishNode(meta, "Identifier");
			this.next();
			var containsEsc = this.containsEsc;
			node.property = this.parseIdent(true);
			if (node.property.name !== "target") this.raiseRecoverable(node.property.start, "The only valid meta property for new is 'new.target'");
			if (containsEsc) this.raiseRecoverable(node.start, "'new.target' must not contain escaped characters");
			if (!this.allowNewDotTarget) this.raiseRecoverable(node.start, "'new.target' can only be used in functions and class static block");
			return this.finishNode(node, "MetaProperty");
		}
		var startPos = this.start, startLoc = this.startLoc;
		node.callee = this.parseSubscripts(this.parseExprAtom(null, false, true), startPos, startLoc, true, false);
		if (node.callee.type === "Super") this.raiseRecoverable(startPos, "Invalid use of 'super'");
		if (this.eat(types$1.parenL)) node.arguments = this.parseExprList(types$1.parenR, this.options.ecmaVersion >= 8, false);
		else node.arguments = empty$2;
		return this.finishNode(node, "NewExpression");
	};
	pp$5.parseTemplateElement = function(ref) {
		var isTagged = ref.isTagged;
		var elem = this.startNode();
		if (this.type === types$1.invalidTemplate) {
			if (!isTagged) this.raiseRecoverable(this.start, "Bad escape sequence in untagged template literal");
			elem.value = {
				raw: this.value.replace(/\r\n?/g, "\n"),
				cooked: null
			};
		} else elem.value = {
			raw: this.input.slice(this.start, this.end).replace(/\r\n?/g, "\n"),
			cooked: this.value
		};
		this.next();
		elem.tail = this.type === types$1.backQuote;
		return this.finishNode(elem, "TemplateElement");
	};
	pp$5.parseTemplate = function(ref) {
		if (ref === void 0) ref = {};
		var isTagged = ref.isTagged;
		if (isTagged === void 0) isTagged = false;
		var node = this.startNode();
		this.next();
		node.expressions = [];
		var curElt = this.parseTemplateElement({ isTagged });
		node.quasis = [curElt];
		while (!curElt.tail) {
			if (this.type === types$1.eof) this.raise(this.pos, "Unterminated template literal");
			this.expect(types$1.dollarBraceL);
			node.expressions.push(this.parseExpression());
			this.expect(types$1.braceR);
			node.quasis.push(curElt = this.parseTemplateElement({ isTagged }));
		}
		this.next();
		return this.finishNode(node, "TemplateLiteral");
	};
	pp$5.isAsyncProp = function(prop) {
		return !prop.computed && prop.key.type === "Identifier" && prop.key.name === "async" && (this.type === types$1.name || this.type === types$1.num || this.type === types$1.string || this.type === types$1.bracketL || this.type.keyword || this.options.ecmaVersion >= 9 && this.type === types$1.star) && !lineBreak.test(this.input.slice(this.lastTokEnd, this.start));
	};
	pp$5.parseObj = function(isPattern, refDestructuringErrors) {
		var node = this.startNode(), first = true, propHash = {};
		node.properties = [];
		this.next();
		while (!this.eat(types$1.braceR)) {
			if (!first) {
				this.expect(types$1.comma);
				if (this.options.ecmaVersion >= 5 && this.afterTrailingComma(types$1.braceR)) break;
			} else first = false;
			var prop = this.parseProperty(isPattern, refDestructuringErrors);
			if (!isPattern) this.checkPropClash(prop, propHash, refDestructuringErrors);
			node.properties.push(prop);
		}
		return this.finishNode(node, isPattern ? "ObjectPattern" : "ObjectExpression");
	};
	pp$5.parseProperty = function(isPattern, refDestructuringErrors) {
		var prop = this.startNode(), isGenerator, isAsync, startPos, startLoc;
		if (this.options.ecmaVersion >= 9 && this.eat(types$1.ellipsis)) {
			if (isPattern) {
				prop.argument = this.parseIdent(false);
				if (this.type === types$1.comma) this.raiseRecoverable(this.start, "Comma is not permitted after the rest element");
				return this.finishNode(prop, "RestElement");
			}
			prop.argument = this.parseMaybeAssign(false, refDestructuringErrors);
			if (this.type === types$1.comma && refDestructuringErrors && refDestructuringErrors.trailingComma < 0) refDestructuringErrors.trailingComma = this.start;
			return this.finishNode(prop, "SpreadElement");
		}
		if (this.options.ecmaVersion >= 6) {
			prop.method = false;
			prop.shorthand = false;
			if (isPattern || refDestructuringErrors) {
				startPos = this.start;
				startLoc = this.startLoc;
			}
			if (!isPattern) isGenerator = this.eat(types$1.star);
		}
		var containsEsc = this.containsEsc;
		this.parsePropertyName(prop);
		if (!isPattern && !containsEsc && this.options.ecmaVersion >= 8 && !isGenerator && this.isAsyncProp(prop)) {
			isAsync = true;
			isGenerator = this.options.ecmaVersion >= 9 && this.eat(types$1.star);
			this.parsePropertyName(prop);
		} else isAsync = false;
		this.parsePropertyValue(prop, isPattern, isGenerator, isAsync, startPos, startLoc, refDestructuringErrors, containsEsc);
		return this.finishNode(prop, "Property");
	};
	pp$5.parseGetterSetter = function(prop) {
		var kind = prop.key.name;
		this.parsePropertyName(prop);
		prop.value = this.parseMethod(false);
		prop.kind = kind;
		var paramCount = prop.kind === "get" ? 0 : 1;
		if (prop.value.params.length !== paramCount) {
			var start = prop.value.start;
			if (prop.kind === "get") this.raiseRecoverable(start, "getter should have no params");
			else this.raiseRecoverable(start, "setter should have exactly one param");
		} else if (prop.kind === "set" && prop.value.params[0].type === "RestElement") this.raiseRecoverable(prop.value.params[0].start, "Setter cannot use rest params");
	};
	pp$5.parsePropertyValue = function(prop, isPattern, isGenerator, isAsync, startPos, startLoc, refDestructuringErrors, containsEsc) {
		if ((isGenerator || isAsync) && this.type === types$1.colon) this.unexpected();
		if (this.eat(types$1.colon)) {
			prop.value = isPattern ? this.parseMaybeDefault(this.start, this.startLoc) : this.parseMaybeAssign(false, refDestructuringErrors);
			prop.kind = "init";
		} else if (this.options.ecmaVersion >= 6 && this.type === types$1.parenL) {
			if (isPattern) this.unexpected();
			prop.method = true;
			prop.value = this.parseMethod(isGenerator, isAsync);
			prop.kind = "init";
		} else if (!isPattern && !containsEsc && this.options.ecmaVersion >= 5 && !prop.computed && prop.key.type === "Identifier" && (prop.key.name === "get" || prop.key.name === "set") && this.type !== types$1.comma && this.type !== types$1.braceR && this.type !== types$1.eq) {
			if (isGenerator || isAsync) this.unexpected();
			this.parseGetterSetter(prop);
		} else if (this.options.ecmaVersion >= 6 && !prop.computed && prop.key.type === "Identifier") {
			if (isGenerator || isAsync) this.unexpected();
			this.checkUnreserved(prop.key);
			if (prop.key.name === "await" && !this.awaitIdentPos) this.awaitIdentPos = startPos;
			if (isPattern) prop.value = this.parseMaybeDefault(startPos, startLoc, this.copyNode(prop.key));
			else if (this.type === types$1.eq && refDestructuringErrors) {
				if (refDestructuringErrors.shorthandAssign < 0) refDestructuringErrors.shorthandAssign = this.start;
				prop.value = this.parseMaybeDefault(startPos, startLoc, this.copyNode(prop.key));
			} else prop.value = this.copyNode(prop.key);
			prop.kind = "init";
			prop.shorthand = true;
		} else this.unexpected();
	};
	pp$5.parsePropertyName = function(prop) {
		if (this.options.ecmaVersion >= 6) {
			if (this.eat(types$1.bracketL)) {
				prop.computed = true;
				prop.key = this.parseMaybeAssign();
				this.expect(types$1.bracketR);
				return prop.key;
			} else prop.computed = false;
		}
		return prop.key = this.type === types$1.num || this.type === types$1.string ? this.parseExprAtom() : this.parseIdent(this.options.allowReserved !== "never");
	};
	pp$5.initFunction = function(node) {
		node.id = null;
		if (this.options.ecmaVersion >= 6) node.generator = node.expression = false;
		if (this.options.ecmaVersion >= 8) node.async = false;
	};
	pp$5.parseMethod = function(isGenerator, isAsync, allowDirectSuper) {
		var node = this.startNode(), oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;
		this.initFunction(node);
		if (this.options.ecmaVersion >= 6) node.generator = isGenerator;
		if (this.options.ecmaVersion >= 8) node.async = !!isAsync;
		this.yieldPos = 0;
		this.awaitPos = 0;
		this.awaitIdentPos = 0;
		this.enterScope(functionFlags(isAsync, node.generator) | SCOPE_SUPER | (allowDirectSuper ? SCOPE_DIRECT_SUPER : 0));
		this.expect(types$1.parenL);
		node.params = this.parseBindingList(types$1.parenR, false, this.options.ecmaVersion >= 8);
		this.checkYieldAwaitInDefaultParams();
		this.parseFunctionBody(node, false, true, false);
		this.yieldPos = oldYieldPos;
		this.awaitPos = oldAwaitPos;
		this.awaitIdentPos = oldAwaitIdentPos;
		return this.finishNode(node, "FunctionExpression");
	};
	pp$5.parseArrowExpression = function(node, params, isAsync, forInit) {
		var oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;
		this.enterScope(functionFlags(isAsync, false) | SCOPE_ARROW);
		this.initFunction(node);
		if (this.options.ecmaVersion >= 8) node.async = !!isAsync;
		this.yieldPos = 0;
		this.awaitPos = 0;
		this.awaitIdentPos = 0;
		node.params = this.toAssignableList(params, true);
		this.parseFunctionBody(node, true, false, forInit);
		this.yieldPos = oldYieldPos;
		this.awaitPos = oldAwaitPos;
		this.awaitIdentPos = oldAwaitIdentPos;
		return this.finishNode(node, "ArrowFunctionExpression");
	};
	pp$5.parseFunctionBody = function(node, isArrowFunction, isMethod, forInit) {
		var isExpression = isArrowFunction && this.type !== types$1.braceL;
		var oldStrict = this.strict, useStrict = false;
		if (isExpression) {
			node.body = this.parseMaybeAssign(forInit);
			node.expression = true;
			this.checkParams(node, false);
		} else {
			var nonSimple = this.options.ecmaVersion >= 7 && !this.isSimpleParamList(node.params);
			if (!oldStrict || nonSimple) {
				useStrict = this.strictDirective(this.end);
				if (useStrict && nonSimple) this.raiseRecoverable(node.start, "Illegal 'use strict' directive in function with non-simple parameter list");
			}
			var oldLabels = this.labels;
			this.labels = [];
			if (useStrict) this.strict = true;
			this.checkParams(node, !oldStrict && !useStrict && !isArrowFunction && !isMethod && this.isSimpleParamList(node.params));
			if (this.strict && node.id) this.checkLValSimple(node.id, BIND_OUTSIDE);
			node.body = this.parseBlock(false, void 0, useStrict && !oldStrict);
			node.expression = false;
			this.adaptDirectivePrologue(node.body.body);
			this.labels = oldLabels;
		}
		this.exitScope();
	};
	pp$5.isSimpleParamList = function(params) {
		for (var i = 0, list = params; i < list.length; i += 1) if (list[i].type !== "Identifier") return false;
		return true;
	};
	pp$5.checkParams = function(node, allowDuplicates) {
		var nameHash = Object.create(null);
		for (var i = 0, list = node.params; i < list.length; i += 1) {
			var param = list[i];
			this.checkLValInnerPattern(param, BIND_VAR, allowDuplicates ? null : nameHash);
		}
	};
	pp$5.parseExprList = function(close, allowTrailingComma, allowEmpty, refDestructuringErrors) {
		var elts = [], first = true;
		while (!this.eat(close)) {
			if (!first) {
				this.expect(types$1.comma);
				if (allowTrailingComma && this.afterTrailingComma(close)) break;
			} else first = false;
			var elt = void 0;
			if (allowEmpty && this.type === types$1.comma) elt = null;
			else if (this.type === types$1.ellipsis) {
				elt = this.parseSpread(refDestructuringErrors);
				if (refDestructuringErrors && this.type === types$1.comma && refDestructuringErrors.trailingComma < 0) refDestructuringErrors.trailingComma = this.start;
			} else elt = this.parseMaybeAssign(false, refDestructuringErrors);
			elts.push(elt);
		}
		return elts;
	};
	pp$5.checkUnreserved = function(ref) {
		var start = ref.start;
		var end = ref.end;
		var name = ref.name;
		if (this.inGenerator && name === "yield") this.raiseRecoverable(start, "Cannot use 'yield' as identifier inside a generator");
		if (this.inAsync && name === "await") this.raiseRecoverable(start, "Cannot use 'await' as identifier inside an async function");
		if (!(this.currentThisScope().flags & SCOPE_VAR) && name === "arguments") this.raiseRecoverable(start, "Cannot use 'arguments' in class field initializer");
		if (this.inClassStaticBlock && (name === "arguments" || name === "await")) this.raise(start, "Cannot use " + name + " in class static initialization block");
		if (this.keywords.test(name)) this.raise(start, "Unexpected keyword '" + name + "'");
		if (this.options.ecmaVersion < 6 && this.input.slice(start, end).indexOf("\\") !== -1) return;
		if ((this.strict ? this.reservedWordsStrict : this.reservedWords).test(name)) {
			if (!this.inAsync && name === "await") this.raiseRecoverable(start, "Cannot use keyword 'await' outside an async function");
			this.raiseRecoverable(start, "The keyword '" + name + "' is reserved");
		}
	};
	pp$5.parseIdent = function(liberal) {
		var node = this.parseIdentNode();
		this.next(!!liberal);
		this.finishNode(node, "Identifier");
		if (!liberal) {
			this.checkUnreserved(node);
			if (node.name === "await" && !this.awaitIdentPos) this.awaitIdentPos = node.start;
		}
		return node;
	};
	pp$5.parseIdentNode = function() {
		var node = this.startNode();
		if (this.type === types$1.name) node.name = this.value;
		else if (this.type.keyword) {
			node.name = this.type.keyword;
			if ((node.name === "class" || node.name === "function") && (this.lastTokEnd !== this.lastTokStart + 1 || this.input.charCodeAt(this.lastTokStart) !== 46)) this.context.pop();
			this.type = types$1.name;
		} else this.unexpected();
		return node;
	};
	pp$5.parsePrivateIdent = function() {
		var node = this.startNode();
		if (this.type === types$1.privateId) node.name = this.value;
		else this.unexpected();
		this.next();
		this.finishNode(node, "PrivateIdentifier");
		if (this.options.checkPrivateFields) {
			if (this.privateNameStack.length === 0) this.raise(node.start, "Private field '#" + node.name + "' must be declared in an enclosing class");
			else this.privateNameStack[this.privateNameStack.length - 1].used.push(node);
		}
		return node;
	};
	pp$5.parseYield = function(forInit) {
		if (!this.yieldPos) this.yieldPos = this.start;
		var node = this.startNode();
		this.next();
		if (this.type === types$1.semi || this.canInsertSemicolon() || this.type !== types$1.star && !this.type.startsExpr) {
			node.delegate = false;
			node.argument = null;
		} else {
			node.delegate = this.eat(types$1.star);
			node.argument = this.parseMaybeAssign(forInit);
		}
		return this.finishNode(node, "YieldExpression");
	};
	pp$5.parseAwait = function(forInit) {
		if (!this.awaitPos) this.awaitPos = this.start;
		var node = this.startNode();
		this.next();
		node.argument = this.parseMaybeUnary(null, true, false, forInit);
		return this.finishNode(node, "AwaitExpression");
	};
	pp$4 = Parser.prototype;
	pp$4.raise = function(pos, message) {
		var loc = getLineInfo(this.input, pos);
		message += " (" + loc.line + ":" + loc.column + ")";
		if (this.sourceFile) message += " in " + this.sourceFile;
		var err = new SyntaxError(message);
		err.pos = pos;
		err.loc = loc;
		err.raisedAt = this.pos;
		throw err;
	};
	pp$4.raiseRecoverable = pp$4.raise;
	pp$4.curPosition = function() {
		if (this.options.locations) return new Position(this.curLine, this.pos - this.lineStart);
	};
	pp$3 = Parser.prototype;
	Scope = function Scope(flags) {
		this.flags = flags;
		this.var = [];
		this.lexical = [];
		this.functions = [];
	};
	pp$3.enterScope = function(flags) {
		this.scopeStack.push(new Scope(flags));
	};
	pp$3.exitScope = function() {
		this.scopeStack.pop();
	};
	pp$3.treatFunctionsAsVarInScope = function(scope) {
		return scope.flags & SCOPE_FUNCTION || !this.inModule && scope.flags & SCOPE_TOP;
	};
	pp$3.declareName = function(name, bindingType, pos) {
		var redeclared = false;
		if (bindingType === BIND_LEXICAL) {
			var scope = this.currentScope();
			redeclared = scope.lexical.indexOf(name) > -1 || scope.functions.indexOf(name) > -1 || scope.var.indexOf(name) > -1;
			scope.lexical.push(name);
			if (this.inModule && scope.flags & SCOPE_TOP) delete this.undefinedExports[name];
		} else if (bindingType === BIND_SIMPLE_CATCH) this.currentScope().lexical.push(name);
		else if (bindingType === BIND_FUNCTION) {
			var scope$2 = this.currentScope();
			if (this.treatFunctionsAsVar) redeclared = scope$2.lexical.indexOf(name) > -1;
			else redeclared = scope$2.lexical.indexOf(name) > -1 || scope$2.var.indexOf(name) > -1;
			scope$2.functions.push(name);
		} else for (var i = this.scopeStack.length - 1; i >= 0; --i) {
			var scope$3 = this.scopeStack[i];
			if (scope$3.lexical.indexOf(name) > -1 && !(scope$3.flags & SCOPE_SIMPLE_CATCH && scope$3.lexical[0] === name) || !this.treatFunctionsAsVarInScope(scope$3) && scope$3.functions.indexOf(name) > -1) {
				redeclared = true;
				break;
			}
			scope$3.var.push(name);
			if (this.inModule && scope$3.flags & SCOPE_TOP) delete this.undefinedExports[name];
			if (scope$3.flags & SCOPE_VAR) break;
		}
		if (redeclared) this.raiseRecoverable(pos, "Identifier '" + name + "' has already been declared");
	};
	pp$3.checkLocalExport = function(id) {
		if (this.scopeStack[0].lexical.indexOf(id.name) === -1 && this.scopeStack[0].var.indexOf(id.name) === -1) this.undefinedExports[id.name] = id;
	};
	pp$3.currentScope = function() {
		return this.scopeStack[this.scopeStack.length - 1];
	};
	pp$3.currentVarScope = function() {
		for (var i = this.scopeStack.length - 1;; i--) {
			var scope = this.scopeStack[i];
			if (scope.flags & (SCOPE_VAR | SCOPE_CLASS_FIELD_INIT | SCOPE_CLASS_STATIC_BLOCK)) return scope;
		}
	};
	pp$3.currentThisScope = function() {
		for (var i = this.scopeStack.length - 1;; i--) {
			var scope = this.scopeStack[i];
			if (scope.flags & (SCOPE_VAR | SCOPE_CLASS_FIELD_INIT | SCOPE_CLASS_STATIC_BLOCK) && !(scope.flags & SCOPE_ARROW)) return scope;
		}
	};
	Node = function Node(parser, pos, loc) {
		this.type = "";
		this.start = pos;
		this.end = 0;
		if (parser.options.locations) this.loc = new SourceLocation(parser, loc);
		if (parser.options.directSourceFile) this.sourceFile = parser.options.directSourceFile;
		if (parser.options.ranges) this.range = [pos, 0];
	};
	pp$2 = Parser.prototype;
	pp$2.startNode = function() {
		return new Node(this, this.start, this.startLoc);
	};
	pp$2.startNodeAt = function(pos, loc) {
		return new Node(this, pos, loc);
	};
	pp$2.finishNode = function(node, type) {
		return finishNodeAt.call(this, node, type, this.lastTokEnd, this.lastTokEndLoc);
	};
	pp$2.finishNodeAt = function(node, type, pos, loc) {
		return finishNodeAt.call(this, node, type, pos, loc);
	};
	pp$2.copyNode = function(node) {
		var newNode = new Node(this, node.start, this.startLoc);
		for (var prop in node) newNode[prop] = node[prop];
		return newNode;
	};
	scriptValuesAddedInUnicode = "Berf Beria_Erfe Gara Garay Gukh Gurung_Khema Hrkt Katakana_Or_Hiragana Kawi Kirat_Rai Krai Nag_Mundari Nagm Ol_Onal Onao Sidetic Sidt Sunu Sunuwar Tai_Yo Tayo Todhri Todr Tolong_Siki Tols Tulu_Tigalari Tutg Unknown Zzzz";
	ecma9BinaryProperties = "ASCII ASCII_Hex_Digit AHex Alphabetic Alpha Any Assigned Bidi_Control Bidi_C Bidi_Mirrored Bidi_M Case_Ignorable CI Cased Changes_When_Casefolded CWCF Changes_When_Casemapped CWCM Changes_When_Lowercased CWL Changes_When_NFKC_Casefolded CWKCF Changes_When_Titlecased CWT Changes_When_Uppercased CWU Dash Default_Ignorable_Code_Point DI Deprecated Dep Diacritic Dia Emoji Emoji_Component Emoji_Modifier Emoji_Modifier_Base Emoji_Presentation Extender Ext Grapheme_Base Gr_Base Grapheme_Extend Gr_Ext Hex_Digit Hex IDS_Binary_Operator IDSB IDS_Trinary_Operator IDST ID_Continue IDC ID_Start IDS Ideographic Ideo Join_Control Join_C Logical_Order_Exception LOE Lowercase Lower Math Noncharacter_Code_Point NChar Pattern_Syntax Pat_Syn Pattern_White_Space Pat_WS Quotation_Mark QMark Radical Regional_Indicator RI Sentence_Terminal STerm Soft_Dotted SD Terminal_Punctuation Term Unified_Ideograph UIdeo Uppercase Upper Variation_Selector VS White_Space space XID_Continue XIDC XID_Start XIDS";
	ecma10BinaryProperties = ecma9BinaryProperties + " Extended_Pictographic";
	ecma11BinaryProperties = ecma10BinaryProperties;
	ecma12BinaryProperties = ecma11BinaryProperties + " EBase EComp EMod EPres ExtPict";
	ecma13BinaryProperties = ecma12BinaryProperties;
	unicodeBinaryProperties = {
		9: ecma9BinaryProperties,
		10: ecma10BinaryProperties,
		11: ecma11BinaryProperties,
		12: ecma12BinaryProperties,
		13: ecma13BinaryProperties,
		14: ecma13BinaryProperties
	};
	unicodeBinaryPropertiesOfStrings = {
		9: "",
		10: "",
		11: "",
		12: "",
		13: "",
		14: "Basic_Emoji Emoji_Keycap_Sequence RGI_Emoji_Modifier_Sequence RGI_Emoji_Flag_Sequence RGI_Emoji_Tag_Sequence RGI_Emoji_ZWJ_Sequence RGI_Emoji"
	};
	unicodeGeneralCategoryValues = "Cased_Letter LC Close_Punctuation Pe Connector_Punctuation Pc Control Cc cntrl Currency_Symbol Sc Dash_Punctuation Pd Decimal_Number Nd digit Enclosing_Mark Me Final_Punctuation Pf Format Cf Initial_Punctuation Pi Letter L Letter_Number Nl Line_Separator Zl Lowercase_Letter Ll Mark M Combining_Mark Math_Symbol Sm Modifier_Letter Lm Modifier_Symbol Sk Nonspacing_Mark Mn Number N Open_Punctuation Ps Other C Other_Letter Lo Other_Number No Other_Punctuation Po Other_Symbol So Paragraph_Separator Zp Private_Use Co Punctuation P punct Separator Z Space_Separator Zs Spacing_Mark Mc Surrogate Cs Symbol S Titlecase_Letter Lt Unassigned Cn Uppercase_Letter Lu";
	ecma9ScriptValues = "Adlam Adlm Ahom Anatolian_Hieroglyphs Hluw Arabic Arab Armenian Armn Avestan Avst Balinese Bali Bamum Bamu Bassa_Vah Bass Batak Batk Bengali Beng Bhaiksuki Bhks Bopomofo Bopo Brahmi Brah Braille Brai Buginese Bugi Buhid Buhd Canadian_Aboriginal Cans Carian Cari Caucasian_Albanian Aghb Chakma Cakm Cham Cham Cherokee Cher Common Zyyy Coptic Copt Qaac Cuneiform Xsux Cypriot Cprt Cyrillic Cyrl Deseret Dsrt Devanagari Deva Duployan Dupl Egyptian_Hieroglyphs Egyp Elbasan Elba Ethiopic Ethi Georgian Geor Glagolitic Glag Gothic Goth Grantha Gran Greek Grek Gujarati Gujr Gurmukhi Guru Han Hani Hangul Hang Hanunoo Hano Hatran Hatr Hebrew Hebr Hiragana Hira Imperial_Aramaic Armi Inherited Zinh Qaai Inscriptional_Pahlavi Phli Inscriptional_Parthian Prti Javanese Java Kaithi Kthi Kannada Knda Katakana Kana Kayah_Li Kali Kharoshthi Khar Khmer Khmr Khojki Khoj Khudawadi Sind Lao Laoo Latin Latn Lepcha Lepc Limbu Limb Linear_A Lina Linear_B Linb Lisu Lisu Lycian Lyci Lydian Lydi Mahajani Mahj Malayalam Mlym Mandaic Mand Manichaean Mani Marchen Marc Masaram_Gondi Gonm Meetei_Mayek Mtei Mende_Kikakui Mend Meroitic_Cursive Merc Meroitic_Hieroglyphs Mero Miao Plrd Modi Mongolian Mong Mro Mroo Multani Mult Myanmar Mymr Nabataean Nbat New_Tai_Lue Talu Newa Newa Nko Nkoo Nushu Nshu Ogham Ogam Ol_Chiki Olck Old_Hungarian Hung Old_Italic Ital Old_North_Arabian Narb Old_Permic Perm Old_Persian Xpeo Old_South_Arabian Sarb Old_Turkic Orkh Oriya Orya Osage Osge Osmanya Osma Pahawh_Hmong Hmng Palmyrene Palm Pau_Cin_Hau Pauc Phags_Pa Phag Phoenician Phnx Psalter_Pahlavi Phlp Rejang Rjng Runic Runr Samaritan Samr Saurashtra Saur Sharada Shrd Shavian Shaw Siddham Sidd SignWriting Sgnw Sinhala Sinh Sora_Sompeng Sora Soyombo Soyo Sundanese Sund Syloti_Nagri Sylo Syriac Syrc Tagalog Tglg Tagbanwa Tagb Tai_Le Tale Tai_Tham Lana Tai_Viet Tavt Takri Takr Tamil Taml Tangut Tang Telugu Telu Thaana Thaa Thai Thai Tibetan Tibt Tifinagh Tfng Tirhuta Tirh Ugaritic Ugar Vai Vaii Warang_Citi Wara Yi Yiii Zanabazar_Square Zanb";
	ecma10ScriptValues = ecma9ScriptValues + " Dogra Dogr Gunjala_Gondi Gong Hanifi_Rohingya Rohg Makasar Maka Medefaidrin Medf Old_Sogdian Sogo Sogdian Sogd";
	ecma11ScriptValues = ecma10ScriptValues + " Elymaic Elym Nandinagari Nand Nyiakeng_Puachue_Hmong Hmnp Wancho Wcho";
	ecma12ScriptValues = ecma11ScriptValues + " Chorasmian Chrs Diak Dives_Akuru Khitan_Small_Script Kits Yezi Yezidi";
	ecma13ScriptValues = ecma12ScriptValues + " Cypro_Minoan Cpmn Old_Uyghur Ougr Tangsa Tnsa Toto Vithkuqi Vith";
	unicodeScriptValues = {
		9: ecma9ScriptValues,
		10: ecma10ScriptValues,
		11: ecma11ScriptValues,
		12: ecma12ScriptValues,
		13: ecma13ScriptValues,
		14: ecma13ScriptValues + " " + scriptValuesAddedInUnicode
	};
	data = {};
	for (i = 0, list = [
		9,
		10,
		11,
		12,
		13,
		14
	]; i < list.length; i += 1) {
		ecmaVersion = list[i];
		buildUnicodeData(ecmaVersion);
	}
	pp$1 = Parser.prototype;
	BranchID = function BranchID(parent, base) {
		this.parent = parent;
		this.base = base || this;
	};
	BranchID.prototype.separatedFrom = function separatedFrom(alt) {
		for (var self = this; self; self = self.parent) for (var other = alt; other; other = other.parent) if (self.base === other.base && self !== other) return true;
		return false;
	};
	BranchID.prototype.sibling = function sibling() {
		return new BranchID(this.parent, this.base);
	};
	RegExpValidationState = function RegExpValidationState(parser) {
		this.parser = parser;
		this.validFlags = "gim" + (parser.options.ecmaVersion >= 6 ? "uy" : "") + (parser.options.ecmaVersion >= 9 ? "s" : "") + (parser.options.ecmaVersion >= 13 ? "d" : "") + (parser.options.ecmaVersion >= 15 ? "v" : "");
		this.unicodeProperties = data[parser.options.ecmaVersion >= 14 ? 14 : parser.options.ecmaVersion];
		this.source = "";
		this.flags = "";
		this.start = 0;
		this.switchU = false;
		this.switchV = false;
		this.switchN = false;
		this.pos = 0;
		this.lastIntValue = 0;
		this.lastStringValue = "";
		this.lastAssertionIsQuantifiable = false;
		this.numCapturingParens = 0;
		this.maxBackReference = 0;
		this.groupNames = Object.create(null);
		this.backReferenceNames = [];
		this.branchID = null;
	};
	RegExpValidationState.prototype.reset = function reset(start, pattern, flags) {
		var unicodeSets = flags.indexOf("v") !== -1;
		var unicode = flags.indexOf("u") !== -1;
		this.start = start | 0;
		this.source = pattern + "";
		this.flags = flags;
		if (unicodeSets && this.parser.options.ecmaVersion >= 15) {
			this.switchU = true;
			this.switchV = true;
			this.switchN = true;
		} else {
			this.switchU = unicode && this.parser.options.ecmaVersion >= 6;
			this.switchV = false;
			this.switchN = unicode && this.parser.options.ecmaVersion >= 9;
		}
	};
	RegExpValidationState.prototype.raise = function raise(message) {
		this.parser.raiseRecoverable(this.start, "Invalid regular expression: /" + this.source + "/: " + message);
	};
	RegExpValidationState.prototype.at = function at(i, forceU) {
		if (forceU === void 0) forceU = false;
		var s = this.source;
		var l = s.length;
		if (i >= l) return -1;
		var c = s.charCodeAt(i);
		if (!(forceU || this.switchU) || c <= 55295 || c >= 57344 || i + 1 >= l) return c;
		var next = s.charCodeAt(i + 1);
		return next >= 56320 && next <= 57343 ? (c << 10) + next - 56613888 : c;
	};
	RegExpValidationState.prototype.nextIndex = function nextIndex(i, forceU) {
		if (forceU === void 0) forceU = false;
		var s = this.source;
		var l = s.length;
		if (i >= l) return l;
		var c = s.charCodeAt(i), next;
		if (!(forceU || this.switchU) || c <= 55295 || c >= 57344 || i + 1 >= l || (next = s.charCodeAt(i + 1)) < 56320 || next > 57343) return i + 1;
		return i + 2;
	};
	RegExpValidationState.prototype.current = function current(forceU) {
		if (forceU === void 0) forceU = false;
		return this.at(this.pos, forceU);
	};
	RegExpValidationState.prototype.lookahead = function lookahead(forceU) {
		if (forceU === void 0) forceU = false;
		return this.at(this.nextIndex(this.pos, forceU), forceU);
	};
	RegExpValidationState.prototype.advance = function advance(forceU) {
		if (forceU === void 0) forceU = false;
		this.pos = this.nextIndex(this.pos, forceU);
	};
	RegExpValidationState.prototype.eat = function eat(ch, forceU) {
		if (forceU === void 0) forceU = false;
		if (this.current(forceU) === ch) {
			this.advance(forceU);
			return true;
		}
		return false;
	};
	RegExpValidationState.prototype.eatChars = function eatChars(chs, forceU) {
		if (forceU === void 0) forceU = false;
		var pos = this.pos;
		for (var i = 0, list = chs; i < list.length; i += 1) {
			var ch = list[i];
			var current = this.at(pos, forceU);
			if (current === -1 || current !== ch) return false;
			pos = this.nextIndex(pos, forceU);
		}
		this.pos = pos;
		return true;
	};
	/**
	* Validate the flags part of a given RegExpLiteral.
	*
	* @param {RegExpValidationState} state The state to validate RegExp.
	* @returns {void}
	*/
	pp$1.validateRegExpFlags = function(state) {
		var validFlags = state.validFlags;
		var flags = state.flags;
		var u = false;
		var v = false;
		for (var i = 0; i < flags.length; i++) {
			var flag = flags.charAt(i);
			if (validFlags.indexOf(flag) === -1) this.raise(state.start, "Invalid regular expression flag");
			if (flags.indexOf(flag, i + 1) > -1) this.raise(state.start, "Duplicate regular expression flag");
			if (flag === "u") u = true;
			if (flag === "v") v = true;
		}
		if (this.options.ecmaVersion >= 15 && u && v) this.raise(state.start, "Invalid regular expression flag");
	};
	/**
	* Validate the pattern part of a given RegExpLiteral.
	*
	* @param {RegExpValidationState} state The state to validate RegExp.
	* @returns {void}
	*/
	pp$1.validateRegExpPattern = function(state) {
		this.regexp_pattern(state);
		if (!state.switchN && this.options.ecmaVersion >= 9 && hasProp(state.groupNames)) {
			state.switchN = true;
			this.regexp_pattern(state);
		}
	};
	pp$1.regexp_pattern = function(state) {
		state.pos = 0;
		state.lastIntValue = 0;
		state.lastStringValue = "";
		state.lastAssertionIsQuantifiable = false;
		state.numCapturingParens = 0;
		state.maxBackReference = 0;
		state.groupNames = Object.create(null);
		state.backReferenceNames.length = 0;
		state.branchID = null;
		this.regexp_disjunction(state);
		if (state.pos !== state.source.length) {
			if (state.eat(41)) state.raise("Unmatched ')'");
			if (state.eat(93) || state.eat(125)) state.raise("Lone quantifier brackets");
		}
		if (state.maxBackReference > state.numCapturingParens) state.raise("Invalid escape");
		for (var i = 0, list = state.backReferenceNames; i < list.length; i += 1) {
			var name = list[i];
			if (!state.groupNames[name]) state.raise("Invalid named capture referenced");
		}
	};
	pp$1.regexp_disjunction = function(state) {
		var trackDisjunction = this.options.ecmaVersion >= 16;
		if (trackDisjunction) state.branchID = new BranchID(state.branchID, null);
		this.regexp_alternative(state);
		while (state.eat(124)) {
			if (trackDisjunction) state.branchID = state.branchID.sibling();
			this.regexp_alternative(state);
		}
		if (trackDisjunction) state.branchID = state.branchID.parent;
		if (this.regexp_eatQuantifier(state, true)) state.raise("Nothing to repeat");
		if (state.eat(123)) state.raise("Lone quantifier brackets");
	};
	pp$1.regexp_alternative = function(state) {
		while (state.pos < state.source.length && this.regexp_eatTerm(state));
	};
	pp$1.regexp_eatTerm = function(state) {
		if (this.regexp_eatAssertion(state)) {
			if (state.lastAssertionIsQuantifiable && this.regexp_eatQuantifier(state)) {
				if (state.switchU) state.raise("Invalid quantifier");
			}
			return true;
		}
		if (state.switchU ? this.regexp_eatAtom(state) : this.regexp_eatExtendedAtom(state)) {
			this.regexp_eatQuantifier(state);
			return true;
		}
		return false;
	};
	pp$1.regexp_eatAssertion = function(state) {
		var start = state.pos;
		state.lastAssertionIsQuantifiable = false;
		if (state.eat(94) || state.eat(36)) return true;
		if (state.eat(92)) {
			if (state.eat(66) || state.eat(98)) return true;
			state.pos = start;
		}
		if (state.eat(40) && state.eat(63)) {
			var lookbehind = false;
			if (this.options.ecmaVersion >= 9) lookbehind = state.eat(60);
			if (state.eat(61) || state.eat(33)) {
				this.regexp_disjunction(state);
				if (!state.eat(41)) state.raise("Unterminated group");
				state.lastAssertionIsQuantifiable = !lookbehind;
				return true;
			}
		}
		state.pos = start;
		return false;
	};
	pp$1.regexp_eatQuantifier = function(state, noError) {
		if (noError === void 0) noError = false;
		if (this.regexp_eatQuantifierPrefix(state, noError)) {
			state.eat(63);
			return true;
		}
		return false;
	};
	pp$1.regexp_eatQuantifierPrefix = function(state, noError) {
		return state.eat(42) || state.eat(43) || state.eat(63) || this.regexp_eatBracedQuantifier(state, noError);
	};
	pp$1.regexp_eatBracedQuantifier = function(state, noError) {
		var start = state.pos;
		if (state.eat(123)) {
			var min = 0, max = -1;
			if (this.regexp_eatDecimalDigits(state)) {
				min = state.lastIntValue;
				if (state.eat(44) && this.regexp_eatDecimalDigits(state)) max = state.lastIntValue;
				if (state.eat(125)) {
					if (max !== -1 && max < min && !noError) state.raise("numbers out of order in {} quantifier");
					return true;
				}
			}
			if (state.switchU && !noError) state.raise("Incomplete quantifier");
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatAtom = function(state) {
		return this.regexp_eatPatternCharacters(state) || state.eat(46) || this.regexp_eatReverseSolidusAtomEscape(state) || this.regexp_eatCharacterClass(state) || this.regexp_eatUncapturingGroup(state) || this.regexp_eatCapturingGroup(state);
	};
	pp$1.regexp_eatReverseSolidusAtomEscape = function(state) {
		var start = state.pos;
		if (state.eat(92)) {
			if (this.regexp_eatAtomEscape(state)) return true;
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatUncapturingGroup = function(state) {
		var start = state.pos;
		if (state.eat(40)) {
			if (state.eat(63)) {
				if (this.options.ecmaVersion >= 16) {
					var addModifiers = this.regexp_eatModifiers(state);
					var hasHyphen = state.eat(45);
					if (addModifiers || hasHyphen) {
						for (var i = 0; i < addModifiers.length; i++) {
							var modifier = addModifiers.charAt(i);
							if (addModifiers.indexOf(modifier, i + 1) > -1) state.raise("Duplicate regular expression modifiers");
						}
						if (hasHyphen) {
							var removeModifiers = this.regexp_eatModifiers(state);
							if (!addModifiers && !removeModifiers && state.current() === 58) state.raise("Invalid regular expression modifiers");
							for (var i$1 = 0; i$1 < removeModifiers.length; i$1++) {
								var modifier$1 = removeModifiers.charAt(i$1);
								if (removeModifiers.indexOf(modifier$1, i$1 + 1) > -1 || addModifiers.indexOf(modifier$1) > -1) state.raise("Duplicate regular expression modifiers");
							}
						}
					}
				}
				if (state.eat(58)) {
					this.regexp_disjunction(state);
					if (state.eat(41)) return true;
					state.raise("Unterminated group");
				}
			}
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatCapturingGroup = function(state) {
		if (state.eat(40)) {
			if (this.options.ecmaVersion >= 9) this.regexp_groupSpecifier(state);
			else if (state.current() === 63) state.raise("Invalid group");
			this.regexp_disjunction(state);
			if (state.eat(41)) {
				state.numCapturingParens += 1;
				return true;
			}
			state.raise("Unterminated group");
		}
		return false;
	};
	pp$1.regexp_eatModifiers = function(state) {
		var modifiers = "";
		var ch = 0;
		while ((ch = state.current()) !== -1 && isRegularExpressionModifier(ch)) {
			modifiers += codePointToString(ch);
			state.advance();
		}
		return modifiers;
	};
	pp$1.regexp_eatExtendedAtom = function(state) {
		return state.eat(46) || this.regexp_eatReverseSolidusAtomEscape(state) || this.regexp_eatCharacterClass(state) || this.regexp_eatUncapturingGroup(state) || this.regexp_eatCapturingGroup(state) || this.regexp_eatInvalidBracedQuantifier(state) || this.regexp_eatExtendedPatternCharacter(state);
	};
	pp$1.regexp_eatInvalidBracedQuantifier = function(state) {
		if (this.regexp_eatBracedQuantifier(state, true)) state.raise("Nothing to repeat");
		return false;
	};
	pp$1.regexp_eatSyntaxCharacter = function(state) {
		var ch = state.current();
		if (isSyntaxCharacter(ch)) {
			state.lastIntValue = ch;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatPatternCharacters = function(state) {
		var start = state.pos;
		var ch = 0;
		while ((ch = state.current()) !== -1 && !isSyntaxCharacter(ch)) state.advance();
		return state.pos !== start;
	};
	pp$1.regexp_eatExtendedPatternCharacter = function(state) {
		var ch = state.current();
		if (ch !== -1 && ch !== 36 && !(ch >= 40 && ch <= 43) && ch !== 46 && ch !== 63 && ch !== 91 && ch !== 94 && ch !== 124) {
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_groupSpecifier = function(state) {
		if (state.eat(63)) {
			if (!this.regexp_eatGroupName(state)) state.raise("Invalid group");
			var trackDisjunction = this.options.ecmaVersion >= 16;
			var known = state.groupNames[state.lastStringValue];
			if (known) {
				if (trackDisjunction) {
					for (var i = 0, list = known; i < list.length; i += 1) if (!list[i].separatedFrom(state.branchID)) state.raise("Duplicate capture group name");
				} else state.raise("Duplicate capture group name");
			}
			if (trackDisjunction) (known || (state.groupNames[state.lastStringValue] = [])).push(state.branchID);
			else state.groupNames[state.lastStringValue] = true;
		}
	};
	pp$1.regexp_eatGroupName = function(state) {
		state.lastStringValue = "";
		if (state.eat(60)) {
			if (this.regexp_eatRegExpIdentifierName(state) && state.eat(62)) return true;
			state.raise("Invalid capture group name");
		}
		return false;
	};
	pp$1.regexp_eatRegExpIdentifierName = function(state) {
		state.lastStringValue = "";
		if (this.regexp_eatRegExpIdentifierStart(state)) {
			state.lastStringValue += codePointToString(state.lastIntValue);
			while (this.regexp_eatRegExpIdentifierPart(state)) state.lastStringValue += codePointToString(state.lastIntValue);
			return true;
		}
		return false;
	};
	pp$1.regexp_eatRegExpIdentifierStart = function(state) {
		var start = state.pos;
		var forceU = this.options.ecmaVersion >= 11;
		var ch = state.current(forceU);
		state.advance(forceU);
		if (ch === 92 && this.regexp_eatRegExpUnicodeEscapeSequence(state, forceU)) ch = state.lastIntValue;
		if (isRegExpIdentifierStart(ch)) {
			state.lastIntValue = ch;
			return true;
		}
		state.pos = start;
		return false;
	};
	pp$1.regexp_eatRegExpIdentifierPart = function(state) {
		var start = state.pos;
		var forceU = this.options.ecmaVersion >= 11;
		var ch = state.current(forceU);
		state.advance(forceU);
		if (ch === 92 && this.regexp_eatRegExpUnicodeEscapeSequence(state, forceU)) ch = state.lastIntValue;
		if (isRegExpIdentifierPart(ch)) {
			state.lastIntValue = ch;
			return true;
		}
		state.pos = start;
		return false;
	};
	pp$1.regexp_eatAtomEscape = function(state) {
		if (this.regexp_eatBackReference(state) || this.regexp_eatCharacterClassEscape(state) || this.regexp_eatCharacterEscape(state) || state.switchN && this.regexp_eatKGroupName(state)) return true;
		if (state.switchU) {
			if (state.current() === 99) state.raise("Invalid unicode escape");
			state.raise("Invalid escape");
		}
		return false;
	};
	pp$1.regexp_eatBackReference = function(state) {
		var start = state.pos;
		if (this.regexp_eatDecimalEscape(state)) {
			var n = state.lastIntValue;
			if (state.switchU) {
				if (n > state.maxBackReference) state.maxBackReference = n;
				return true;
			}
			if (n <= state.numCapturingParens) return true;
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatKGroupName = function(state) {
		if (state.eat(107)) {
			if (this.regexp_eatGroupName(state)) {
				state.backReferenceNames.push(state.lastStringValue);
				return true;
			}
			state.raise("Invalid named reference");
		}
		return false;
	};
	pp$1.regexp_eatCharacterEscape = function(state) {
		return this.regexp_eatControlEscape(state) || this.regexp_eatCControlLetter(state) || this.regexp_eatZero(state) || this.regexp_eatHexEscapeSequence(state) || this.regexp_eatRegExpUnicodeEscapeSequence(state, false) || !state.switchU && this.regexp_eatLegacyOctalEscapeSequence(state) || this.regexp_eatIdentityEscape(state);
	};
	pp$1.regexp_eatCControlLetter = function(state) {
		var start = state.pos;
		if (state.eat(99)) {
			if (this.regexp_eatControlLetter(state)) return true;
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatZero = function(state) {
		if (state.current() === 48 && !isDecimalDigit(state.lookahead())) {
			state.lastIntValue = 0;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatControlEscape = function(state) {
		var ch = state.current();
		if (ch === 116) {
			state.lastIntValue = 9;
			state.advance();
			return true;
		}
		if (ch === 110) {
			state.lastIntValue = 10;
			state.advance();
			return true;
		}
		if (ch === 118) {
			state.lastIntValue = 11;
			state.advance();
			return true;
		}
		if (ch === 102) {
			state.lastIntValue = 12;
			state.advance();
			return true;
		}
		if (ch === 114) {
			state.lastIntValue = 13;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatControlLetter = function(state) {
		var ch = state.current();
		if (isControlLetter(ch)) {
			state.lastIntValue = ch % 32;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatRegExpUnicodeEscapeSequence = function(state, forceU) {
		if (forceU === void 0) forceU = false;
		var start = state.pos;
		var switchU = forceU || state.switchU;
		if (state.eat(117)) {
			if (this.regexp_eatFixedHexDigits(state, 4)) {
				var lead = state.lastIntValue;
				if (switchU && lead >= 55296 && lead <= 56319) {
					var leadSurrogateEnd = state.pos;
					if (state.eat(92) && state.eat(117) && this.regexp_eatFixedHexDigits(state, 4)) {
						var trail = state.lastIntValue;
						if (trail >= 56320 && trail <= 57343) {
							state.lastIntValue = (lead - 55296) * 1024 + (trail - 56320) + 65536;
							return true;
						}
					}
					state.pos = leadSurrogateEnd;
					state.lastIntValue = lead;
				}
				return true;
			}
			if (switchU && state.eat(123) && this.regexp_eatHexDigits(state) && state.eat(125) && isValidUnicode(state.lastIntValue)) return true;
			if (switchU) state.raise("Invalid unicode escape");
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatIdentityEscape = function(state) {
		if (state.switchU) {
			if (this.regexp_eatSyntaxCharacter(state)) return true;
			if (state.eat(47)) {
				state.lastIntValue = 47;
				return true;
			}
			return false;
		}
		var ch = state.current();
		if (ch !== 99 && (!state.switchN || ch !== 107)) {
			state.lastIntValue = ch;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatDecimalEscape = function(state) {
		state.lastIntValue = 0;
		var ch = state.current();
		if (ch >= 49 && ch <= 57) {
			do {
				state.lastIntValue = 10 * state.lastIntValue + (ch - 48);
				state.advance();
			} while ((ch = state.current()) >= 48 && ch <= 57);
			return true;
		}
		return false;
	};
	CharSetNone = 0;
	CharSetOk = 1;
	CharSetString = 2;
	pp$1.regexp_eatCharacterClassEscape = function(state) {
		var ch = state.current();
		if (isCharacterClassEscape(ch)) {
			state.lastIntValue = -1;
			state.advance();
			return CharSetOk;
		}
		var negate = false;
		if (state.switchU && this.options.ecmaVersion >= 9 && ((negate = ch === 80) || ch === 112)) {
			state.lastIntValue = -1;
			state.advance();
			var result;
			if (state.eat(123) && (result = this.regexp_eatUnicodePropertyValueExpression(state)) && state.eat(125)) {
				if (negate && result === CharSetString) state.raise("Invalid property name");
				return result;
			}
			state.raise("Invalid property name");
		}
		return CharSetNone;
	};
	pp$1.regexp_eatUnicodePropertyValueExpression = function(state) {
		var start = state.pos;
		if (this.regexp_eatUnicodePropertyName(state) && state.eat(61)) {
			var name = state.lastStringValue;
			if (this.regexp_eatUnicodePropertyValue(state)) {
				var value = state.lastStringValue;
				this.regexp_validateUnicodePropertyNameAndValue(state, name, value);
				return CharSetOk;
			}
		}
		state.pos = start;
		if (this.regexp_eatLoneUnicodePropertyNameOrValue(state)) {
			var nameOrValue = state.lastStringValue;
			return this.regexp_validateUnicodePropertyNameOrValue(state, nameOrValue);
		}
		return CharSetNone;
	};
	pp$1.regexp_validateUnicodePropertyNameAndValue = function(state, name, value) {
		if (!hasOwn(state.unicodeProperties.nonBinary, name)) state.raise("Invalid property name");
		if (!state.unicodeProperties.nonBinary[name].test(value)) state.raise("Invalid property value");
	};
	pp$1.regexp_validateUnicodePropertyNameOrValue = function(state, nameOrValue) {
		if (state.unicodeProperties.binary.test(nameOrValue)) return CharSetOk;
		if (state.switchV && state.unicodeProperties.binaryOfStrings.test(nameOrValue)) return CharSetString;
		state.raise("Invalid property name");
	};
	pp$1.regexp_eatUnicodePropertyName = function(state) {
		var ch = 0;
		state.lastStringValue = "";
		while (isUnicodePropertyNameCharacter(ch = state.current())) {
			state.lastStringValue += codePointToString(ch);
			state.advance();
		}
		return state.lastStringValue !== "";
	};
	pp$1.regexp_eatUnicodePropertyValue = function(state) {
		var ch = 0;
		state.lastStringValue = "";
		while (isUnicodePropertyValueCharacter(ch = state.current())) {
			state.lastStringValue += codePointToString(ch);
			state.advance();
		}
		return state.lastStringValue !== "";
	};
	pp$1.regexp_eatLoneUnicodePropertyNameOrValue = function(state) {
		return this.regexp_eatUnicodePropertyValue(state);
	};
	pp$1.regexp_eatCharacterClass = function(state) {
		if (state.eat(91)) {
			var negate = state.eat(94);
			var result = this.regexp_classContents(state);
			if (!state.eat(93)) state.raise("Unterminated character class");
			if (negate && result === CharSetString) state.raise("Negated character class may contain strings");
			return true;
		}
		return false;
	};
	pp$1.regexp_classContents = function(state) {
		if (state.current() === 93) return CharSetOk;
		if (state.switchV) return this.regexp_classSetExpression(state);
		this.regexp_nonEmptyClassRanges(state);
		return CharSetOk;
	};
	pp$1.regexp_nonEmptyClassRanges = function(state) {
		while (this.regexp_eatClassAtom(state)) {
			var left = state.lastIntValue;
			if (state.eat(45) && this.regexp_eatClassAtom(state)) {
				var right = state.lastIntValue;
				if (state.switchU && (left === -1 || right === -1)) state.raise("Invalid character class");
				if (left !== -1 && right !== -1 && left > right) state.raise("Range out of order in character class");
			}
		}
	};
	pp$1.regexp_eatClassAtom = function(state) {
		var start = state.pos;
		if (state.eat(92)) {
			if (this.regexp_eatClassEscape(state)) return true;
			if (state.switchU) {
				var ch$1 = state.current();
				if (ch$1 === 99 || isOctalDigit(ch$1)) state.raise("Invalid class escape");
				state.raise("Invalid escape");
			}
			state.pos = start;
		}
		var ch = state.current();
		if (ch !== 93) {
			state.lastIntValue = ch;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatClassEscape = function(state) {
		var start = state.pos;
		if (state.eat(98)) {
			state.lastIntValue = 8;
			return true;
		}
		if (state.switchU && state.eat(45)) {
			state.lastIntValue = 45;
			return true;
		}
		if (!state.switchU && state.eat(99)) {
			if (this.regexp_eatClassControlLetter(state)) return true;
			state.pos = start;
		}
		return this.regexp_eatCharacterClassEscape(state) || this.regexp_eatCharacterEscape(state);
	};
	pp$1.regexp_classSetExpression = function(state) {
		var result = CharSetOk, subResult;
		if (this.regexp_eatClassSetRange(state));
		else if (subResult = this.regexp_eatClassSetOperand(state)) {
			if (subResult === CharSetString) result = CharSetString;
			var start = state.pos;
			while (state.eatChars([38, 38])) {
				if (state.current() !== 38 && (subResult = this.regexp_eatClassSetOperand(state))) {
					if (subResult !== CharSetString) result = CharSetOk;
					continue;
				}
				state.raise("Invalid character in character class");
			}
			if (start !== state.pos) return result;
			while (state.eatChars([45, 45])) {
				if (this.regexp_eatClassSetOperand(state)) continue;
				state.raise("Invalid character in character class");
			}
			if (start !== state.pos) return result;
		} else state.raise("Invalid character in character class");
		for (;;) {
			if (this.regexp_eatClassSetRange(state)) continue;
			subResult = this.regexp_eatClassSetOperand(state);
			if (!subResult) return result;
			if (subResult === CharSetString) result = CharSetString;
		}
	};
	pp$1.regexp_eatClassSetRange = function(state) {
		var start = state.pos;
		if (this.regexp_eatClassSetCharacter(state)) {
			var left = state.lastIntValue;
			if (state.eat(45) && this.regexp_eatClassSetCharacter(state)) {
				var right = state.lastIntValue;
				if (left !== -1 && right !== -1 && left > right) state.raise("Range out of order in character class");
				return true;
			}
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatClassSetOperand = function(state) {
		if (this.regexp_eatClassSetCharacter(state)) return CharSetOk;
		return this.regexp_eatClassStringDisjunction(state) || this.regexp_eatNestedClass(state);
	};
	pp$1.regexp_eatNestedClass = function(state) {
		var start = state.pos;
		if (state.eat(91)) {
			var negate = state.eat(94);
			var result = this.regexp_classContents(state);
			if (state.eat(93)) {
				if (negate && result === CharSetString) state.raise("Negated character class may contain strings");
				return result;
			}
			state.pos = start;
		}
		if (state.eat(92)) {
			var result$1 = this.regexp_eatCharacterClassEscape(state);
			if (result$1) return result$1;
			state.pos = start;
		}
		return null;
	};
	pp$1.regexp_eatClassStringDisjunction = function(state) {
		var start = state.pos;
		if (state.eatChars([92, 113])) {
			if (state.eat(123)) {
				var result = this.regexp_classStringDisjunctionContents(state);
				if (state.eat(125)) return result;
			} else state.raise("Invalid escape");
			state.pos = start;
		}
		return null;
	};
	pp$1.regexp_classStringDisjunctionContents = function(state) {
		var result = this.regexp_classString(state);
		while (state.eat(124)) if (this.regexp_classString(state) === CharSetString) result = CharSetString;
		return result;
	};
	pp$1.regexp_classString = function(state) {
		var count = 0;
		while (this.regexp_eatClassSetCharacter(state)) count++;
		return count === 1 ? CharSetOk : CharSetString;
	};
	pp$1.regexp_eatClassSetCharacter = function(state) {
		var start = state.pos;
		if (state.eat(92)) {
			if (this.regexp_eatCharacterEscape(state) || this.regexp_eatClassSetReservedPunctuator(state)) return true;
			if (state.eat(98)) {
				state.lastIntValue = 8;
				return true;
			}
			state.pos = start;
			return false;
		}
		var ch = state.current();
		if (ch < 0 || ch === state.lookahead() && isClassSetReservedDoublePunctuatorCharacter(ch)) return false;
		if (isClassSetSyntaxCharacter(ch)) return false;
		state.advance();
		state.lastIntValue = ch;
		return true;
	};
	pp$1.regexp_eatClassSetReservedPunctuator = function(state) {
		var ch = state.current();
		if (isClassSetReservedPunctuator(ch)) {
			state.lastIntValue = ch;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatClassControlLetter = function(state) {
		var ch = state.current();
		if (isDecimalDigit(ch) || ch === 95) {
			state.lastIntValue = ch % 32;
			state.advance();
			return true;
		}
		return false;
	};
	pp$1.regexp_eatHexEscapeSequence = function(state) {
		var start = state.pos;
		if (state.eat(120)) {
			if (this.regexp_eatFixedHexDigits(state, 2)) return true;
			if (state.switchU) state.raise("Invalid escape");
			state.pos = start;
		}
		return false;
	};
	pp$1.regexp_eatDecimalDigits = function(state) {
		var start = state.pos;
		var ch = 0;
		state.lastIntValue = 0;
		while (isDecimalDigit(ch = state.current())) {
			state.lastIntValue = 10 * state.lastIntValue + (ch - 48);
			state.advance();
		}
		return state.pos !== start;
	};
	pp$1.regexp_eatHexDigits = function(state) {
		var start = state.pos;
		var ch = 0;
		state.lastIntValue = 0;
		while (isHexDigit(ch = state.current())) {
			state.lastIntValue = 16 * state.lastIntValue + hexToInt(ch);
			state.advance();
		}
		return state.pos !== start;
	};
	pp$1.regexp_eatLegacyOctalEscapeSequence = function(state) {
		if (this.regexp_eatOctalDigit(state)) {
			var n1 = state.lastIntValue;
			if (this.regexp_eatOctalDigit(state)) {
				var n2 = state.lastIntValue;
				if (n1 <= 3 && this.regexp_eatOctalDigit(state)) state.lastIntValue = n1 * 64 + n2 * 8 + state.lastIntValue;
				else state.lastIntValue = n1 * 8 + n2;
			} else state.lastIntValue = n1;
			return true;
		}
		return false;
	};
	pp$1.regexp_eatOctalDigit = function(state) {
		var ch = state.current();
		if (isOctalDigit(ch)) {
			state.lastIntValue = ch - 48;
			state.advance();
			return true;
		}
		state.lastIntValue = 0;
		return false;
	};
	pp$1.regexp_eatFixedHexDigits = function(state, length) {
		var start = state.pos;
		state.lastIntValue = 0;
		for (var i = 0; i < length; ++i) {
			var ch = state.current();
			if (!isHexDigit(ch)) {
				state.pos = start;
				return false;
			}
			state.lastIntValue = 16 * state.lastIntValue + hexToInt(ch);
			state.advance();
		}
		return true;
	};
	Token = function Token(p) {
		this.type = p.type;
		this.value = p.value;
		this.start = p.start;
		this.end = p.end;
		if (p.options.locations) this.loc = new SourceLocation(p, p.startLoc, p.endLoc);
		if (p.options.ranges) this.range = [p.start, p.end];
	};
	pp = Parser.prototype;
	pp.next = function(ignoreEscapeSequenceInKeyword) {
		if (!ignoreEscapeSequenceInKeyword && this.type.keyword && this.containsEsc) this.raiseRecoverable(this.start, "Escape sequence in keyword " + this.type.keyword);
		if (this.options.onToken) this.options.onToken(new Token(this));
		this.lastTokEnd = this.end;
		this.lastTokStart = this.start;
		this.lastTokEndLoc = this.endLoc;
		this.lastTokStartLoc = this.startLoc;
		this.nextToken();
	};
	pp.getToken = function() {
		this.next();
		return new Token(this);
	};
	if (typeof Symbol !== "undefined") pp[Symbol.iterator] = function() {
		var this$1$1 = this;
		return { next: function() {
			var token = this$1$1.getToken();
			return {
				done: token.type === types$1.eof,
				value: token
			};
		} };
	};
	pp.nextToken = function() {
		var curContext = this.curContext();
		if (!curContext || !curContext.preserveSpace) this.skipSpace();
		this.start = this.pos;
		if (this.options.locations) this.startLoc = this.curPosition();
		if (this.pos >= this.input.length) return this.finishToken(types$1.eof);
		if (curContext.override) return curContext.override(this);
		else this.readToken(this.fullCharCodeAtPos());
	};
	pp.readToken = function(code) {
		if (isIdentifierStart(code, this.options.ecmaVersion >= 6) || code === 92) return this.readWord();
		return this.getTokenFromCode(code);
	};
	pp.fullCharCodeAt = function(pos) {
		var code = this.input.charCodeAt(pos);
		if (code <= 55295 || code >= 56320) return code;
		var next = this.input.charCodeAt(pos + 1);
		return next <= 56319 || next >= 57344 ? code : (code << 10) + next - 56613888;
	};
	pp.fullCharCodeAtPos = function() {
		return this.fullCharCodeAt(this.pos);
	};
	pp.skipBlockComment = function() {
		var startLoc = this.options.onComment && this.curPosition();
		var start = this.pos, end = this.input.indexOf("*/", this.pos += 2);
		if (end === -1) this.raise(this.pos - 2, "Unterminated comment");
		this.pos = end + 2;
		if (this.options.locations) for (var nextBreak = void 0, pos = start; (nextBreak = nextLineBreak(this.input, pos, this.pos)) > -1;) {
			++this.curLine;
			pos = this.lineStart = nextBreak;
		}
		if (this.options.onComment) this.options.onComment(true, this.input.slice(start + 2, end), start, this.pos, startLoc, this.curPosition());
	};
	pp.skipLineComment = function(startSkip) {
		var start = this.pos;
		var startLoc = this.options.onComment && this.curPosition();
		var ch = this.input.charCodeAt(this.pos += startSkip);
		while (this.pos < this.input.length && !isNewLine(ch)) ch = this.input.charCodeAt(++this.pos);
		if (this.options.onComment) this.options.onComment(false, this.input.slice(start + startSkip, this.pos), start, this.pos, startLoc, this.curPosition());
	};
	pp.skipSpace = function() {
		loop: while (this.pos < this.input.length) {
			var ch = this.input.charCodeAt(this.pos);
			switch (ch) {
				case 32:
				case 160:
					++this.pos;
					break;
				case 13: if (this.input.charCodeAt(this.pos + 1) === 10) ++this.pos;
				case 10:
				case 8232:
				case 8233:
					++this.pos;
					if (this.options.locations) {
						++this.curLine;
						this.lineStart = this.pos;
					}
					break;
				case 47:
					switch (this.input.charCodeAt(this.pos + 1)) {
						case 42:
							this.skipBlockComment();
							break;
						case 47:
							this.skipLineComment(2);
							break;
						default: break loop;
					}
					break;
				default: if (ch > 8 && ch < 14 || ch >= 5760 && nonASCIIwhitespace.test(String.fromCharCode(ch))) ++this.pos;
				else break loop;
			}
		}
	};
	pp.finishToken = function(type, val) {
		this.end = this.pos;
		if (this.options.locations) this.endLoc = this.curPosition();
		var prevType = this.type;
		this.type = type;
		this.value = val;
		this.updateContext(prevType);
	};
	pp.readToken_dot = function() {
		var next = this.input.charCodeAt(this.pos + 1);
		if (next >= 48 && next <= 57) return this.readNumber(true);
		var next2 = this.input.charCodeAt(this.pos + 2);
		if (this.options.ecmaVersion >= 6 && next === 46 && next2 === 46) {
			this.pos += 3;
			return this.finishToken(types$1.ellipsis);
		} else {
			++this.pos;
			return this.finishToken(types$1.dot);
		}
	};
	pp.readToken_slash = function() {
		var next = this.input.charCodeAt(this.pos + 1);
		if (this.exprAllowed) {
			++this.pos;
			return this.readRegexp();
		}
		if (next === 61) return this.finishOp(types$1.assign, 2);
		return this.finishOp(types$1.slash, 1);
	};
	pp.readToken_mult_modulo_exp = function(code) {
		var next = this.input.charCodeAt(this.pos + 1);
		var size = 1;
		var tokentype = code === 42 ? types$1.star : types$1.modulo;
		if (this.options.ecmaVersion >= 7 && code === 42 && next === 42) {
			++size;
			tokentype = types$1.starstar;
			next = this.input.charCodeAt(this.pos + 2);
		}
		if (next === 61) return this.finishOp(types$1.assign, size + 1);
		return this.finishOp(tokentype, size);
	};
	pp.readToken_pipe_amp = function(code) {
		var next = this.input.charCodeAt(this.pos + 1);
		if (next === code) {
			if (this.options.ecmaVersion >= 12) {
				if (this.input.charCodeAt(this.pos + 2) === 61) return this.finishOp(types$1.assign, 3);
			}
			return this.finishOp(code === 124 ? types$1.logicalOR : types$1.logicalAND, 2);
		}
		if (next === 61) return this.finishOp(types$1.assign, 2);
		return this.finishOp(code === 124 ? types$1.bitwiseOR : types$1.bitwiseAND, 1);
	};
	pp.readToken_caret = function() {
		if (this.input.charCodeAt(this.pos + 1) === 61) return this.finishOp(types$1.assign, 2);
		return this.finishOp(types$1.bitwiseXOR, 1);
	};
	pp.readToken_plus_min = function(code) {
		var next = this.input.charCodeAt(this.pos + 1);
		if (next === code) {
			if (next === 45 && !this.inModule && this.input.charCodeAt(this.pos + 2) === 62 && (this.lastTokEnd === 0 || lineBreak.test(this.input.slice(this.lastTokEnd, this.pos)))) {
				this.skipLineComment(3);
				this.skipSpace();
				return this.nextToken();
			}
			return this.finishOp(types$1.incDec, 2);
		}
		if (next === 61) return this.finishOp(types$1.assign, 2);
		return this.finishOp(types$1.plusMin, 1);
	};
	pp.readToken_lt_gt = function(code) {
		var next = this.input.charCodeAt(this.pos + 1);
		var size = 1;
		if (next === code) {
			size = code === 62 && this.input.charCodeAt(this.pos + 2) === 62 ? 3 : 2;
			if (this.input.charCodeAt(this.pos + size) === 61) return this.finishOp(types$1.assign, size + 1);
			return this.finishOp(types$1.bitShift, size);
		}
		if (next === 33 && code === 60 && !this.inModule && this.input.charCodeAt(this.pos + 2) === 45 && this.input.charCodeAt(this.pos + 3) === 45) {
			this.skipLineComment(4);
			this.skipSpace();
			return this.nextToken();
		}
		if (next === 61) size = 2;
		return this.finishOp(types$1.relational, size);
	};
	pp.readToken_eq_excl = function(code) {
		var next = this.input.charCodeAt(this.pos + 1);
		if (next === 61) return this.finishOp(types$1.equality, this.input.charCodeAt(this.pos + 2) === 61 ? 3 : 2);
		if (code === 61 && next === 62 && this.options.ecmaVersion >= 6) {
			this.pos += 2;
			return this.finishToken(types$1.arrow);
		}
		return this.finishOp(code === 61 ? types$1.eq : types$1.prefix, 1);
	};
	pp.readToken_question = function() {
		var ecmaVersion = this.options.ecmaVersion;
		if (ecmaVersion >= 11) {
			var next = this.input.charCodeAt(this.pos + 1);
			if (next === 46) {
				var next2 = this.input.charCodeAt(this.pos + 2);
				if (next2 < 48 || next2 > 57) return this.finishOp(types$1.questionDot, 2);
			}
			if (next === 63) {
				if (ecmaVersion >= 12) {
					if (this.input.charCodeAt(this.pos + 2) === 61) return this.finishOp(types$1.assign, 3);
				}
				return this.finishOp(types$1.coalesce, 2);
			}
		}
		return this.finishOp(types$1.question, 1);
	};
	pp.readToken_numberSign = function() {
		var ecmaVersion = this.options.ecmaVersion;
		var code = 35;
		if (ecmaVersion >= 13) {
			++this.pos;
			code = this.fullCharCodeAtPos();
			if (isIdentifierStart(code, true) || code === 92) return this.finishToken(types$1.privateId, this.readWord1());
		}
		this.raise(this.pos, "Unexpected character '" + codePointToString(code) + "'");
	};
	pp.getTokenFromCode = function(code) {
		switch (code) {
			case 46: return this.readToken_dot();
			case 40:
				++this.pos;
				return this.finishToken(types$1.parenL);
			case 41:
				++this.pos;
				return this.finishToken(types$1.parenR);
			case 59:
				++this.pos;
				return this.finishToken(types$1.semi);
			case 44:
				++this.pos;
				return this.finishToken(types$1.comma);
			case 91:
				++this.pos;
				return this.finishToken(types$1.bracketL);
			case 93:
				++this.pos;
				return this.finishToken(types$1.bracketR);
			case 123:
				++this.pos;
				return this.finishToken(types$1.braceL);
			case 125:
				++this.pos;
				return this.finishToken(types$1.braceR);
			case 58:
				++this.pos;
				return this.finishToken(types$1.colon);
			case 96:
				if (this.options.ecmaVersion < 6) break;
				++this.pos;
				return this.finishToken(types$1.backQuote);
			case 48:
				var next = this.input.charCodeAt(this.pos + 1);
				if (next === 120 || next === 88) return this.readRadixNumber(16);
				if (this.options.ecmaVersion >= 6) {
					if (next === 111 || next === 79) return this.readRadixNumber(8);
					if (next === 98 || next === 66) return this.readRadixNumber(2);
				}
			case 49:
			case 50:
			case 51:
			case 52:
			case 53:
			case 54:
			case 55:
			case 56:
			case 57: return this.readNumber(false);
			case 34:
			case 39: return this.readString(code);
			case 47: return this.readToken_slash();
			case 37:
			case 42: return this.readToken_mult_modulo_exp(code);
			case 124:
			case 38: return this.readToken_pipe_amp(code);
			case 94: return this.readToken_caret();
			case 43:
			case 45: return this.readToken_plus_min(code);
			case 60:
			case 62: return this.readToken_lt_gt(code);
			case 61:
			case 33: return this.readToken_eq_excl(code);
			case 63: return this.readToken_question();
			case 126: return this.finishOp(types$1.prefix, 1);
			case 35: return this.readToken_numberSign();
		}
		this.raise(this.pos, "Unexpected character '" + codePointToString(code) + "'");
	};
	pp.finishOp = function(type, size) {
		var str = this.input.slice(this.pos, this.pos + size);
		this.pos += size;
		return this.finishToken(type, str);
	};
	pp.readRegexp = function() {
		var escaped, inClass, start = this.pos;
		for (;;) {
			if (this.pos >= this.input.length) this.raise(start, "Unterminated regular expression");
			var ch = this.input.charAt(this.pos);
			if (lineBreak.test(ch)) this.raise(start, "Unterminated regular expression");
			if (!escaped) {
				if (ch === "[") inClass = true;
				else if (ch === "]" && inClass) inClass = false;
				else if (ch === "/" && !inClass) break;
				escaped = ch === "\\";
			} else escaped = false;
			++this.pos;
		}
		var pattern = this.input.slice(start, this.pos);
		++this.pos;
		var flagsStart = this.pos;
		var flags = this.readWord1();
		if (this.containsEsc) this.unexpected(flagsStart);
		var state = this.regexpState || (this.regexpState = new RegExpValidationState(this));
		state.reset(start, pattern, flags);
		this.validateRegExpFlags(state);
		this.validateRegExpPattern(state);
		var value = null;
		try {
			value = new RegExp(pattern, flags);
		} catch (e) {}
		return this.finishToken(types$1.regexp, {
			pattern,
			flags,
			value
		});
	};
	pp.readInt = function(radix, len, maybeLegacyOctalNumericLiteral) {
		var allowSeparators = this.options.ecmaVersion >= 12 && len === void 0;
		var isLegacyOctalNumericLiteral = maybeLegacyOctalNumericLiteral && this.input.charCodeAt(this.pos) === 48;
		var start = this.pos, total = 0, lastCode = 0;
		for (var i = 0, e = len == null ? Infinity : len; i < e; ++i, ++this.pos) {
			var code = this.input.charCodeAt(this.pos), val = void 0;
			if (allowSeparators && code === 95) {
				if (isLegacyOctalNumericLiteral) this.raiseRecoverable(this.pos, "Numeric separator is not allowed in legacy octal numeric literals");
				if (lastCode === 95) this.raiseRecoverable(this.pos, "Numeric separator must be exactly one underscore");
				if (i === 0) this.raiseRecoverable(this.pos, "Numeric separator is not allowed at the first of digits");
				lastCode = code;
				continue;
			}
			if (code >= 97) val = code - 97 + 10;
			else if (code >= 65) val = code - 65 + 10;
			else if (code >= 48 && code <= 57) val = code - 48;
			else val = Infinity;
			if (val >= radix) break;
			lastCode = code;
			total = total * radix + val;
		}
		if (allowSeparators && lastCode === 95) this.raiseRecoverable(this.pos - 1, "Numeric separator is not allowed at the last of digits");
		if (this.pos === start || len != null && this.pos - start !== len) return null;
		return total;
	};
	pp.readRadixNumber = function(radix) {
		var start = this.pos;
		this.pos += 2;
		var val = this.readInt(radix);
		if (val == null) this.raise(this.start + 2, "Expected number in radix " + radix);
		if (this.options.ecmaVersion >= 11 && this.input.charCodeAt(this.pos) === 110) {
			val = stringToBigInt(this.input.slice(start, this.pos));
			++this.pos;
		} else if (isIdentifierStart(this.fullCharCodeAtPos())) this.raise(this.pos, "Identifier directly after number");
		return this.finishToken(types$1.num, val);
	};
	pp.readNumber = function(startsWithDot) {
		var start = this.pos;
		if (!startsWithDot && this.readInt(10, void 0, true) === null) this.raise(start, "Invalid number");
		var octal = this.pos - start >= 2 && this.input.charCodeAt(start) === 48;
		if (octal && this.strict) this.raise(start, "Invalid number");
		var next = this.input.charCodeAt(this.pos);
		if (!octal && !startsWithDot && this.options.ecmaVersion >= 11 && next === 110) {
			var val$1 = stringToBigInt(this.input.slice(start, this.pos));
			++this.pos;
			if (isIdentifierStart(this.fullCharCodeAtPos())) this.raise(this.pos, "Identifier directly after number");
			return this.finishToken(types$1.num, val$1);
		}
		if (octal && /[89]/.test(this.input.slice(start, this.pos))) octal = false;
		if (next === 46 && !octal) {
			++this.pos;
			this.readInt(10);
			next = this.input.charCodeAt(this.pos);
		}
		if ((next === 69 || next === 101) && !octal) {
			next = this.input.charCodeAt(++this.pos);
			if (next === 43 || next === 45) ++this.pos;
			if (this.readInt(10) === null) this.raise(start, "Invalid number");
		}
		if (isIdentifierStart(this.fullCharCodeAtPos())) this.raise(this.pos, "Identifier directly after number");
		var val = stringToNumber(this.input.slice(start, this.pos), octal);
		return this.finishToken(types$1.num, val);
	};
	pp.readCodePoint = function() {
		var ch = this.input.charCodeAt(this.pos), code;
		if (ch === 123) {
			if (this.options.ecmaVersion < 6) this.unexpected();
			var codePos = ++this.pos;
			code = this.readHexChar(this.input.indexOf("}", this.pos) - this.pos);
			++this.pos;
			if (code > 1114111) this.invalidStringToken(codePos, "Code point out of bounds");
		} else code = this.readHexChar(4);
		return code;
	};
	pp.readString = function(quote) {
		var out = "", chunkStart = ++this.pos;
		for (;;) {
			if (this.pos >= this.input.length) this.raise(this.start, "Unterminated string constant");
			var ch = this.input.charCodeAt(this.pos);
			if (ch === quote) break;
			if (ch === 92) {
				out += this.input.slice(chunkStart, this.pos);
				out += this.readEscapedChar(false);
				chunkStart = this.pos;
			} else if (ch === 8232 || ch === 8233) {
				if (this.options.ecmaVersion < 10) this.raise(this.start, "Unterminated string constant");
				++this.pos;
				if (this.options.locations) {
					this.curLine++;
					this.lineStart = this.pos;
				}
			} else {
				if (isNewLine(ch)) this.raise(this.start, "Unterminated string constant");
				++this.pos;
			}
		}
		out += this.input.slice(chunkStart, this.pos++);
		return this.finishToken(types$1.string, out);
	};
	INVALID_TEMPLATE_ESCAPE_ERROR = {};
	pp.tryReadTemplateToken = function() {
		this.inTemplateElement = true;
		try {
			this.readTmplToken();
		} catch (err) {
			if (err === INVALID_TEMPLATE_ESCAPE_ERROR) this.readInvalidTemplateToken();
			else throw err;
		}
		this.inTemplateElement = false;
	};
	pp.invalidStringToken = function(position, message) {
		if (this.inTemplateElement && this.options.ecmaVersion >= 9) throw INVALID_TEMPLATE_ESCAPE_ERROR;
		else this.raise(position, message);
	};
	pp.readTmplToken = function() {
		var out = "", chunkStart = this.pos;
		for (;;) {
			if (this.pos >= this.input.length) this.raise(this.start, "Unterminated template");
			var ch = this.input.charCodeAt(this.pos);
			if (ch === 96 || ch === 36 && this.input.charCodeAt(this.pos + 1) === 123) {
				if (this.pos === this.start && (this.type === types$1.template || this.type === types$1.invalidTemplate)) {
					if (ch === 36) {
						this.pos += 2;
						return this.finishToken(types$1.dollarBraceL);
					} else {
						++this.pos;
						return this.finishToken(types$1.backQuote);
					}
				}
				out += this.input.slice(chunkStart, this.pos);
				return this.finishToken(types$1.template, out);
			}
			if (ch === 92) {
				out += this.input.slice(chunkStart, this.pos);
				out += this.readEscapedChar(true);
				chunkStart = this.pos;
			} else if (isNewLine(ch)) {
				out += this.input.slice(chunkStart, this.pos);
				++this.pos;
				switch (ch) {
					case 13: if (this.input.charCodeAt(this.pos) === 10) ++this.pos;
					case 10:
						out += "\n";
						break;
					default: out += String.fromCharCode(ch);
				}
				if (this.options.locations) {
					++this.curLine;
					this.lineStart = this.pos;
				}
				chunkStart = this.pos;
			} else ++this.pos;
		}
	};
	pp.readInvalidTemplateToken = function() {
		for (; this.pos < this.input.length; this.pos++) switch (this.input[this.pos]) {
			case "\\":
				++this.pos;
				break;
			case "$": if (this.input[this.pos + 1] !== "{") break;
			case "`": return this.finishToken(types$1.invalidTemplate, this.input.slice(this.start, this.pos));
			case "\r": if (this.input[this.pos + 1] === "\n") ++this.pos;
			case "\n":
			case "\u2028":
			case "\u2029":
				++this.curLine;
				this.lineStart = this.pos + 1;
		}
		this.raise(this.start, "Unterminated template");
	};
	pp.readEscapedChar = function(inTemplate) {
		var ch = this.input.charCodeAt(++this.pos);
		++this.pos;
		switch (ch) {
			case 110: return "\n";
			case 114: return "\r";
			case 120: return String.fromCharCode(this.readHexChar(2));
			case 117: return codePointToString(this.readCodePoint());
			case 116: return "	";
			case 98: return "\b";
			case 118: return "\v";
			case 102: return "\f";
			case 13: if (this.input.charCodeAt(this.pos) === 10) ++this.pos;
			case 10:
				if (this.options.locations) {
					this.lineStart = this.pos;
					++this.curLine;
				}
				return "";
			case 56:
			case 57:
				if (this.strict) this.invalidStringToken(this.pos - 1, "Invalid escape sequence");
				if (inTemplate) {
					var codePos = this.pos - 1;
					this.invalidStringToken(codePos, "Invalid escape sequence in template string");
				}
			default:
				if (ch >= 48 && ch <= 55) {
					var octalStr = this.input.substr(this.pos - 1, 3).match(/^[0-7]+/)[0];
					var octal = parseInt(octalStr, 8);
					if (octal > 255) {
						octalStr = octalStr.slice(0, -1);
						octal = parseInt(octalStr, 8);
					}
					this.pos += octalStr.length - 1;
					ch = this.input.charCodeAt(this.pos);
					if ((octalStr !== "0" || ch === 56 || ch === 57) && (this.strict || inTemplate)) this.invalidStringToken(this.pos - 1 - octalStr.length, inTemplate ? "Octal literal in template string" : "Octal literal in strict mode");
					return String.fromCharCode(octal);
				}
				if (isNewLine(ch)) {
					if (this.options.locations) {
						this.lineStart = this.pos;
						++this.curLine;
					}
					return "";
				}
				return String.fromCharCode(ch);
		}
	};
	pp.readHexChar = function(len) {
		var codePos = this.pos;
		var n = this.readInt(16, len);
		if (n === null) this.invalidStringToken(codePos, "Bad character escape sequence");
		return n;
	};
	pp.readWord1 = function() {
		this.containsEsc = false;
		var word = "", first = true, chunkStart = this.pos;
		var astral = this.options.ecmaVersion >= 6;
		while (this.pos < this.input.length) {
			var ch = this.fullCharCodeAtPos();
			if (isIdentifierChar(ch, astral)) this.pos += ch <= 65535 ? 1 : 2;
			else if (ch === 92) {
				this.containsEsc = true;
				word += this.input.slice(chunkStart, this.pos);
				var escStart = this.pos;
				if (this.input.charCodeAt(++this.pos) !== 117) this.invalidStringToken(this.pos, "Expecting Unicode escape sequence \\uXXXX");
				++this.pos;
				var esc = this.readCodePoint();
				if (!(first ? isIdentifierStart : isIdentifierChar)(esc, astral)) this.invalidStringToken(escStart, "Invalid Unicode escape");
				word += codePointToString(esc);
				chunkStart = this.pos;
			} else break;
			first = false;
		}
		return word + this.input.slice(chunkStart, this.pos);
	};
	pp.readWord = function() {
		var word = this.readWord1();
		var type = types$1.name;
		if (this.keywords.test(word)) type = keywords[word];
		return this.finishToken(type, word);
	};
	version = "8.19.0";
	Parser.acorn = {
		Parser,
		version,
		defaultOptions,
		Position,
		SourceLocation,
		getLineInfo,
		Node,
		TokenType,
		tokTypes: types$1,
		keywordTypes: keywords,
		TokContext,
		tokContexts: types,
		isIdentifierChar,
		isIdentifierStart,
		Token,
		isNewLine,
		lineBreak,
		lineBreakG,
		nonASCIIwhitespace
	};
}));
// ../packages/analyzer/src/parse.ts
/** Parses as an ES module first, then as a script. Returns the error message if both fail. */
function parseJs(text) {
	try {
		return { program: parse(text, {
			...BASE,
			sourceType: "module"
		}) };
	} catch (moduleErr) {
		try {
			return { program: parse(text, {
				...BASE,
				sourceType: "script"
			}) };
		} catch (scriptErr) {
			const err = errorPos(moduleErr) > errorPos(scriptErr) ? moduleErr : scriptErr;
			return { error: err instanceof Error ? err.message : "parse error" };
		}
	}
}
var errorPos, BASE;
var init_parse = __esmMin((() => {
	init_acorn();
	errorPos = (e) => e.pos ?? -1;
	BASE = {
		ecmaVersion: "latest",
		allowHashBang: true,
		allowReturnOutsideFunction: true,
		locations: true
	};
}));
// ../packages/analyzer/src/scripts.ts
/**
* Reads the install scripts from a parsed package.json. Like npm, a `binding.gyp` with
* no `install`/`preinstall` script implies `install: node-gyp rebuild`.
* See https://docs.npmjs.com/cli/v11/using-npm/scripts#npm-install
*/
function readInstallScripts(pkg, hasBindingGyp) {
	const raw = pkg["scripts"];
	const scripts = raw !== null && typeof raw === "object" ? raw : {};
	const out = {};
	for (const k of [...INSTALL_HOOKS, "prepare"]) {
		const v = scripts[k];
		if (typeof v === "string" && v.trim() !== "") out[k] = v;
	}
	if (hasBindingGyp && out.install === void 0 && out.preinstall === void 0) out.install = "node-gyp rebuild";
	return out;
}
/** Why a script string itself looks network-capable, or `undefined`. */
function scriptNetworkReason(script) {
	return NETWORK_PATTERNS.find((p) => p.re.test(script))?.why;
}
/** Splits a script into words, dropping shell operators and surrounding quotes. Best-effort. */
function words(script) {
	return script.split(/\s+|&&|\|\||[;|&()]/).map((w) => w.replace(/^['"]|['"]$/g, "")).filter((w) => w !== "");
}
/**
* Package files that a script may run with node: any word ending in `.js`/`.cjs`/`.mjs`,
* and the first non-flag argument after `node`. Returned as raw words; resolve them with
* {@link resolveLocal}.
*/
function scriptEntryWords(script) {
	const ws = words(script);
	const out = /* @__PURE__ */ new Set();
	for (let i = 0; i < ws.length; i++) {
		const w = ws[i] ?? "";
		if (/\.[cm]?js$/i.test(w)) out.add(w);
		if (/^(?:.*[/\\])?node(?:\.exe)?$/i.test(w)) {
			const next = ws.slice(i + 1).find((x) => !x.startsWith("-"));
			if (next !== void 0) out.add(next);
		}
	}
	return [...out];
}
/**
* Resolves a relative path (from `fromDir`, package-relative) to a file in `has`, trying
* the extensions and `index` files Node would. Returns `undefined` outside the package.
*/
function resolveLocal(fromDir, spec, has) {
	const joined = posix.normalize(posix.join(fromDir, spec.replaceAll("\\", "/")));
	if (joined === ".." || joined.startsWith("../") || posix.isAbsolute(joined)) return void 0;
	const base = joined.replace(/\/$/, "");
	for (const c of [
		base,
		`${base}.js`,
		`${base}.cjs`,
		`${base}.mjs`,
		`${base}/index.js`,
		`${base}/index.cjs`,
		`${base}/index.mjs`
	]) if (has(c)) return c;
}
var INSTALL_HOOKS, NETWORK_PATTERNS;
var init_scripts = __esmMin((() => {
	INSTALL_HOOKS = [
		"preinstall",
		"install",
		"postinstall"
	];
	NETWORK_PATTERNS = [
		{
			re: /(?:^|[\s;&|(`])(?:curl|wget)(?:\.exe)?(?=$|[\s;&|)`])/i,
			why: "runs curl/wget"
		},
		{
			re: /(?:^|[\s;&|(`])node(?:\.exe)?\s+(?:[^\s;&|]+\s+)*?(?:-e|--eval|-p|--print)(?=$|[\s=])/i,
			why: "runs inline code with node -e"
		},
		{
			re: /\b(?:https?|ftp):\/\//i,
			why: "contains a URL"
		},
		{
			re: /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|certutil|bitsadmin)\b/i,
			why: "runs a Windows download tool"
		}
	];
}));
// ../packages/analyzer/src/signals.ts
/** Builds a signal with its default severity, deduplicating and capping the evidence. */
function makeSignal(id, message, evidence, maxEvidence) {
	const seen = /* @__PURE__ */ new Set();
	const unique = [];
	for (const e of evidence) {
		const key = JSON.stringify([
			e.file,
			e.line,
			e.snippet,
			e.detail
		]);
		if (!seen.has(key)) {
			seen.add(key);
			unique.push(e);
		}
	}
	unique.sort((a, b) => cmp$1(a.file, b.file) || (a.line ?? 0) - (b.line ?? 0) || cmp$1(a.snippet, b.snippet) || cmp$1(a.detail, b.detail));
	const kept = unique.slice(0, maxEvidence);
	if (unique.length > maxEvidence) kept.push({ detail: `and ${unique.length - maxEvidence} more` });
	return {
		id,
		severity: SIGNAL_SEVERITY[id],
		message,
		evidence: kept
	};
}
/** Sort comparator: severity, then id, then first evidence file, then message. */
function compareSignals(a, b) {
	return compareSeverity(a.severity, b.severity) || cmp$1(a.id, b.id) || cmp$1(a.evidence[0]?.file, b.evidence[0]?.file) || cmp$1(a.message, b.message);
}
/** Converts a profile's signals to {@link Finding}s, sorted by severity, package, then id. */
function profileFindings(profile) {
	return profile.signals.map((s) => ({
		id: s.id,
		severity: s.severity,
		package: profile.name,
		version: profile.version,
		message: s.message,
		evidence: s.evidence,
		docsUrl: findingDocsUrl(s.id)
	})).toSorted(compareFindings);
}
var SIGNAL_SEVERITY, cmp$1;
var init_signals = __esmMin((() => {
	init_src$1();
	SIGNAL_SEVERITY = {
		"install-script": "medium",
		"install-script-network": "high",
		"env-sensitive-read": "high",
		"env-exfil-pattern": "critical",
		"fs-sensitive-path": "high",
		obfuscation: "high",
		"encoded-payload": "high",
		"high-entropy-string": "low",
		"hardcoded-endpoint": "info",
		"raw-ip-endpoint": "medium",
		"native-binary": "medium",
		"unparseable-file": "low",
		"oversized-file": "low",
		"minified-only": "info"
	};
	cmp$1 = (a, b) => (a ?? "") < (b ?? "") ? -1 : (a ?? "") > (b ?? "") ? 1 : 0;
}));
// ../packages/analyzer/src/text.ts
/** Strips ANSI escapes and control characters, collapses whitespace, and truncates. */
function clean(s, max = 120) {
	const out = s.replace(ANSI, "").replace(CONTROL, " ");
	return out.length > max ? `${out.slice(0, max - 1)}…` : out;
}
/** Shannon entropy in bits per character (UTF-16 code units). */
function shannonEntropy(s) {
	if (s.length === 0) return 0;
	const counts = /* @__PURE__ */ new Map();
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		counts.set(c, (counts.get(c) ?? 0) + 1);
	}
	let h = 0;
	for (const n of counts.values()) {
		const p = n / s.length;
		h -= p * Math.log2(p);
	}
	return h;
}
/** True for env var names that usually hold credentials (spec: `env-sensitive-read`). */
function isSensitiveEnvKey(key) {
	return SECRET_WORD.test(key) || VENDOR_PREFIX.test(key);
}
/** Returns what kind of sensitive location a string literal points at, or `null`. */
function sensitivePath(s) {
	if (s.length > 4096) return null;
	const segs = s.toLowerCase().split(/[/\\]/);
	for (const rule of SENSITIVE_PATHS) {
		const n = rule.segments.length;
		for (let i = 0; i + n <= segs.length; i++) if (rule.segments.every((seg, j) => segs[i + j] === seg)) return rule.what;
	}
	return null;
}
/** True for loopback and unspecified addresses (`127.0.0.0/8`, `0.0.0.0`, `::1`, `::`). */
function isLoopbackIp(ip) {
	const v = ip.replace(/^\[|\]$/g, "");
	return v.startsWith("127.") || v === "0.0.0.0" || v === "::1" || v === "::";
}
/** True when a host should not be reported as an endpoint. */
function isIgnoredHost(host) {
	const h = host.toLowerCase().replace(/\.$/, "");
	if (IGNORED_HOSTS.has(h) || isLoopbackIp(h)) return true;
	if (RESERVED_SUFFIXES.some((s) => h.endsWith(s))) return true;
	return /(?:^|\.)example\.(?:com|net|org)$/.test(h);
}
/**
* Extracts endpoints from a string literal: URLs anywhere in it, or the whole literal
* when it is an IP (optionally with a port) or a hostname with a common TLD. Set
* `hostContext` when the literal is a `host`/`hostname` value, so any hostname counts.
* Reserved, loopback, and documentation hosts are dropped.
*/
function findEndpoints(s, hostContext = false) {
	if (s.length > 1e6) return [];
	const out = [];
	for (const m of s.matchAll(URL_RE)) {
		let url;
		try {
			url = new URL(m[0]);
		} catch {
			continue;
		}
		const host = url.hostname.replace(/^\[|\]$/g, "");
		if (!host || isIgnoredHost(host)) continue;
		const endpoint = `${url.protocol}//${url.host}${url.pathname === "/" ? "" : url.pathname}`;
		out.push({
			endpoint: endpoint.slice(0, 200),
			host,
			ip: isIP(host) !== 0
		});
	}
	if (out.length > 0) return out;
	const whole = s.trim();
	const v4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/.exec(whole)?.[1];
	const v6 = /^\[([0-9a-f:.]+)\](?::\d{1,5})?$/i.exec(whole)?.[1] ?? (isIP(whole) === 6 ? whole : void 0);
	const ip = v4 !== void 0 && isIP(v4) === 4 ? v4 : v6 !== void 0 && isIP(v6) === 6 ? v6 : void 0;
	if (ip !== void 0) return isLoopbackIp(ip) ? [] : [{
		endpoint: whole,
		host: ip,
		ip: true
	}];
	const hm = HOSTNAME.exec(whole);
	if (hm && (hostContext || HOST_TLDS.has((hm[1] ?? "").toLowerCase())) && !isIgnoredHost(whole)) out.push({
		endpoint: whole.toLowerCase(),
		host: whole.toLowerCase(),
		ip: false
	});
	return out;
}
/** Counts escapes (`\xNN`, `\uNNNN`, `\u{N}`) in raw literal source that decode to printable ASCII. */
function countAsciiEscapes(raw) {
	let n = 0;
	for (const m of raw.matchAll(/\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\})/g)) {
		const code = Number.parseInt(m[1] ?? m[2] ?? m[3] ?? "", 16);
		if (code >= 32 && code < 127) n++;
	}
	return n;
}
/** True for a base64/base64url or hex literal (whitespace ignored) longer than `minLength`. */
function isEncodedBlob(s, minLength = 1024) {
	if (s.length <= minLength) return false;
	const compact = s.replace(/\s+/g, "");
	return compact.length > minLength && (HEX.test(compact) || BASE64.test(compact));
}
var ANSI, CONTROL, SECRET_WORD, VENDOR_PREFIX, SENSITIVE_PATHS, RESERVED_SUFFIXES, IGNORED_HOSTS, HOST_TLDS, HOSTNAME, URL_RE, BASE64, HEX;
var init_text = __esmMin((() => {
	ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
	CONTROL = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(31, 127)}-${String.fromCharCode(159, 8232, 8233)}]+`, "g");
	SECRET_WORD = /TOKEN|SECRET|KEY|PASSWORD/i;
	VENDOR_PREFIX = /^(?:NPM_|AWS_|GITHUB_|GH_|CI_JOB)/;
	SENSITIVE_PATHS = [
		{
			what: "npm credentials",
			segments: [".npmrc"]
		},
		{
			what: "SSH keys",
			segments: [".ssh"]
		},
		{
			what: "SSH keys",
			segments: ["id_rsa"]
		},
		{
			what: "SSH keys",
			segments: ["id_ed25519"]
		},
		{
			what: "AWS credentials",
			segments: [".aws"]
		},
		{
			what: "git credentials",
			segments: [".git-credentials"]
		},
		{
			what: "GitHub CLI credentials",
			segments: [".config", "gh"]
		},
		{
			what: "browser profile",
			segments: ["chrome", "user data"]
		},
		{
			what: "browser profile",
			segments: ["chromium", "user data"]
		},
		{
			what: "browser profile",
			segments: ["brave-browser", "user data"]
		},
		{
			what: "browser profile",
			segments: ["edge", "user data"]
		},
		{
			what: "browser profile",
			segments: [".config", "google-chrome"]
		},
		{
			what: "browser profile",
			segments: [".config", "chromium"]
		},
		{
			what: "browser profile",
			segments: [".mozilla", "firefox"]
		},
		{
			what: "browser profile",
			segments: ["firefox", "profiles"]
		},
		{
			what: "browser credentials",
			segments: ["login data"]
		},
		{
			what: "wallet keystore",
			segments: [".ethereum", "keystore"]
		},
		{
			what: "wallet keystore",
			segments: ["ethereum", "keystore"]
		},
		{
			what: "wallet keystore",
			segments: ["wallet.dat"]
		},
		{
			what: "wallet keystore",
			segments: [".electrum"]
		},
		{
			what: "wallet keystore",
			segments: [".solana", "id.json"]
		},
		{
			what: "wallet keystore",
			segments: ["exodus", "exodus.wallet"]
		},
		{
			what: "wallet keystore",
			segments: ["nkbihfbeogaeaoehlefnkodbefgpgknn"]
		}
	];
	RESERVED_SUFFIXES = [
		".example",
		".test",
		".localhost",
		".local"
	];
	IGNORED_HOSTS = /* @__PURE__ */ new Set([
		"localhost",
		"example.com",
		"example.net",
		"example.org",
		"w3.org",
		"www.w3.org",
		"github.com",
		"www.github.com",
		"npmjs.com",
		"www.npmjs.com",
		"docs.npmjs.com",
		"nodejs.org",
		"developer.mozilla.org",
		"tc39.es",
		"json-schema.org",
		"opensource.org",
		"spdx.org",
		"tools.ietf.org",
		"datatracker.ietf.org",
		"www.rfc-editor.org",
		"schemas.xmlsoap.org",
		"schemas.microsoft.com",
		"purl.org",
		"xmlns.com",
		"mths.be",
		"en.wikipedia.org",
		"stackoverflow.com"
	]);
	HOST_TLDS = new Set("com net org io dev app ru cn xyz top sh co me info biz cc tk pw su site online live cloud ws in to gg ly".split(" "));
	HOSTNAME = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})$/i;
	URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'`<>()\\{}|^]+/gi;
	BASE64 = /^[A-Za-z0-9+/_-]+={0,2}$/;
	HEX = /^(?:[0-9a-fA-F]{2})+$/;
}));
// ../packages/analyzer/src/types.ts
var CAPABILITIES;
var init_types = __esmMin((() => {
	CAPABILITIES = [
		"fs",
		"net",
		"child_process",
		"env",
		"dynamic_code",
		"native_addon",
		"worker",
		"dynamic_require",
		"crypto",
		"os_info"
	];
}));
// ../node_modules/.pnpm/acorn-walk@8.3.5/node_modules/acorn-walk/dist/walk.mjs
function full(node, callback, baseVisitor, state, override) {
	if (!baseVisitor) baseVisitor = base;
	var last;
	(function c(node, st, override) {
		var type = override || node.type;
		visitNode(baseVisitor, type, node, st, c);
		if (last !== node) {
			callback(node, st, type);
			last = node;
		}
	})(node, state, override);
}
function fullAncestor(node, callback, baseVisitor, state) {
	if (!baseVisitor) baseVisitor = base;
	var ancestors = [], last;
	(function c(node, st, override) {
		var type = override || node.type;
		var isNew = node !== ancestors[ancestors.length - 1];
		if (isNew) ancestors.push(node);
		visitNode(baseVisitor, type, node, st, c);
		if (last !== node) {
			callback(node, st || ancestors, ancestors, type);
			last = node;
		}
		if (isNew) ancestors.pop();
	})(node, state);
}
function skipThrough(node, st, c) {
	c(node, st);
}
function ignore(_node, _st, _c) {}
function visitNode(baseVisitor, type, node, st, c) {
	if (baseVisitor[type] == null) throw new Error("No walker function defined for node type " + type);
	baseVisitor[type](node, st, c);
}
var base;
var init_walk = __esmMin((() => {
	base = {};
	base.Program = base.BlockStatement = base.StaticBlock = function(node, st, c) {
		for (var i = 0, list = node.body; i < list.length; i += 1) {
			var stmt = list[i];
			c(stmt, st, "Statement");
		}
	};
	base.Statement = skipThrough;
	base.EmptyStatement = ignore;
	base.ExpressionStatement = base.ParenthesizedExpression = base.ChainExpression = function(node, st, c) {
		return c(node.expression, st, "Expression");
	};
	base.IfStatement = function(node, st, c) {
		c(node.test, st, "Expression");
		c(node.consequent, st, "Statement");
		if (node.alternate) c(node.alternate, st, "Statement");
	};
	base.LabeledStatement = function(node, st, c) {
		return c(node.body, st, "Statement");
	};
	base.BreakStatement = base.ContinueStatement = ignore;
	base.WithStatement = function(node, st, c) {
		c(node.object, st, "Expression");
		c(node.body, st, "Statement");
	};
	base.SwitchStatement = function(node, st, c) {
		c(node.discriminant, st, "Expression");
		for (var i = 0, list = node.cases; i < list.length; i += 1) {
			var cs = list[i];
			c(cs, st);
		}
	};
	base.SwitchCase = function(node, st, c) {
		if (node.test) c(node.test, st, "Expression");
		for (var i = 0, list = node.consequent; i < list.length; i += 1) {
			var cons = list[i];
			c(cons, st, "Statement");
		}
	};
	base.ReturnStatement = base.YieldExpression = base.AwaitExpression = function(node, st, c) {
		if (node.argument) c(node.argument, st, "Expression");
	};
	base.ThrowStatement = base.SpreadElement = function(node, st, c) {
		return c(node.argument, st, "Expression");
	};
	base.TryStatement = function(node, st, c) {
		c(node.block, st, "Statement");
		if (node.handler) c(node.handler, st);
		if (node.finalizer) c(node.finalizer, st, "Statement");
	};
	base.CatchClause = function(node, st, c) {
		if (node.param) c(node.param, st, "Pattern");
		c(node.body, st, "Statement");
	};
	base.WhileStatement = base.DoWhileStatement = function(node, st, c) {
		c(node.test, st, "Expression");
		c(node.body, st, "Statement");
	};
	base.ForStatement = function(node, st, c) {
		if (node.init) c(node.init, st, "ForInit");
		if (node.test) c(node.test, st, "Expression");
		if (node.update) c(node.update, st, "Expression");
		c(node.body, st, "Statement");
	};
	base.ForInStatement = base.ForOfStatement = function(node, st, c) {
		c(node.left, st, "ForInit");
		c(node.right, st, "Expression");
		c(node.body, st, "Statement");
	};
	base.ForInit = function(node, st, c) {
		if (node.type === "VariableDeclaration") c(node, st);
		else c(node, st, "Expression");
	};
	base.DebuggerStatement = ignore;
	base.FunctionDeclaration = function(node, st, c) {
		return c(node, st, "Function");
	};
	base.VariableDeclaration = function(node, st, c) {
		for (var i = 0, list = node.declarations; i < list.length; i += 1) {
			var decl = list[i];
			c(decl, st);
		}
	};
	base.VariableDeclarator = function(node, st, c) {
		c(node.id, st, "Pattern");
		if (node.init) c(node.init, st, "Expression");
	};
	base.Function = function(node, st, c) {
		if (node.id) c(node.id, st, "Pattern");
		for (var i = 0, list = node.params; i < list.length; i += 1) {
			var param = list[i];
			c(param, st, "Pattern");
		}
		c(node.body, st, node.expression ? "Expression" : "Statement");
	};
	base.Pattern = function(node, st, c) {
		if (node.type === "Identifier") c(node, st, "VariablePattern");
		else if (node.type === "MemberExpression") c(node, st, "MemberPattern");
		else c(node, st);
	};
	base.VariablePattern = ignore;
	base.MemberPattern = skipThrough;
	base.RestElement = function(node, st, c) {
		return c(node.argument, st, "Pattern");
	};
	base.ArrayPattern = function(node, st, c) {
		for (var i = 0, list = node.elements; i < list.length; i += 1) {
			var elt = list[i];
			if (elt) c(elt, st, "Pattern");
		}
	};
	base.ObjectPattern = function(node, st, c) {
		for (var i = 0, list = node.properties; i < list.length; i += 1) {
			var prop = list[i];
			if (prop.type === "Property") {
				if (prop.computed) c(prop.key, st, "Expression");
				c(prop.value, st, "Pattern");
			} else if (prop.type === "RestElement") c(prop.argument, st, "Pattern");
		}
	};
	base.Expression = skipThrough;
	base.ThisExpression = base.Super = base.MetaProperty = ignore;
	base.ArrayExpression = function(node, st, c) {
		for (var i = 0, list = node.elements; i < list.length; i += 1) {
			var elt = list[i];
			if (elt) c(elt, st, "Expression");
		}
	};
	base.ObjectExpression = function(node, st, c) {
		for (var i = 0, list = node.properties; i < list.length; i += 1) {
			var prop = list[i];
			c(prop, st);
		}
	};
	base.FunctionExpression = base.ArrowFunctionExpression = base.FunctionDeclaration;
	base.SequenceExpression = function(node, st, c) {
		for (var i = 0, list = node.expressions; i < list.length; i += 1) {
			var expr = list[i];
			c(expr, st, "Expression");
		}
	};
	base.TemplateLiteral = function(node, st, c) {
		for (var i = 0, list = node.quasis; i < list.length; i += 1) {
			var quasi = list[i];
			c(quasi, st);
		}
		for (var i$1 = 0, list$1 = node.expressions; i$1 < list$1.length; i$1 += 1) {
			var expr = list$1[i$1];
			c(expr, st, "Expression");
		}
	};
	base.TemplateElement = ignore;
	base.UnaryExpression = base.UpdateExpression = function(node, st, c) {
		c(node.argument, st, "Expression");
	};
	base.BinaryExpression = base.LogicalExpression = function(node, st, c) {
		c(node.left, st, "Expression");
		c(node.right, st, "Expression");
	};
	base.AssignmentExpression = base.AssignmentPattern = function(node, st, c) {
		c(node.left, st, "Pattern");
		c(node.right, st, "Expression");
	};
	base.ConditionalExpression = function(node, st, c) {
		c(node.test, st, "Expression");
		c(node.consequent, st, "Expression");
		c(node.alternate, st, "Expression");
	};
	base.NewExpression = base.CallExpression = function(node, st, c) {
		c(node.callee, st, "Expression");
		if (node.arguments) for (var i = 0, list = node.arguments; i < list.length; i += 1) {
			var arg = list[i];
			c(arg, st, "Expression");
		}
	};
	base.MemberExpression = function(node, st, c) {
		c(node.object, st, "Expression");
		if (node.computed) c(node.property, st, "Expression");
	};
	base.ExportNamedDeclaration = base.ExportDefaultDeclaration = function(node, st, c) {
		if (node.declaration) c(node.declaration, st, node.type === "ExportNamedDeclaration" || node.declaration.id ? "Statement" : "Expression");
		if (node.source) c(node.source, st, "Expression");
		if (node.attributes) for (var i = 0, list = node.attributes; i < list.length; i += 1) {
			var attr = list[i];
			c(attr, st);
		}
	};
	base.ExportAllDeclaration = function(node, st, c) {
		if (node.exported) c(node.exported, st);
		c(node.source, st, "Expression");
		if (node.attributes) for (var i = 0, list = node.attributes; i < list.length; i += 1) {
			var attr = list[i];
			c(attr, st);
		}
	};
	base.ImportAttribute = function(node, st, c) {
		c(node.value, st, "Expression");
	};
	base.ImportDeclaration = function(node, st, c) {
		for (var i = 0, list = node.specifiers; i < list.length; i += 1) {
			var spec = list[i];
			c(spec, st);
		}
		c(node.source, st, "Expression");
		if (node.attributes) for (var i$1 = 0, list$1 = node.attributes; i$1 < list$1.length; i$1 += 1) {
			var attr = list$1[i$1];
			c(attr, st);
		}
	};
	base.ImportExpression = function(node, st, c) {
		c(node.source, st, "Expression");
		if (node.options) c(node.options, st, "Expression");
	};
	base.ImportSpecifier = base.ImportDefaultSpecifier = base.ImportNamespaceSpecifier = base.Identifier = base.PrivateIdentifier = base.Literal = ignore;
	base.TaggedTemplateExpression = function(node, st, c) {
		c(node.tag, st, "Expression");
		c(node.quasi, st, "Expression");
	};
	base.ClassDeclaration = base.ClassExpression = function(node, st, c) {
		return c(node, st, "Class");
	};
	base.Class = function(node, st, c) {
		if (node.id) c(node.id, st, "Pattern");
		if (node.superClass) c(node.superClass, st, "Expression");
		c(node.body, st);
	};
	base.ClassBody = function(node, st, c) {
		for (var i = 0, list = node.body; i < list.length; i += 1) {
			var elt = list[i];
			c(elt, st);
		}
	};
	base.MethodDefinition = base.PropertyDefinition = base.Property = function(node, st, c) {
		if (node.computed) c(node.key, st, "Expression");
		if (node.value) c(node.value, st, "Expression");
	};
}));
// ../packages/analyzer/src/bindings.ts
/**
* Normalizes a module specifier: builtins lose `node:` and their subpath (`node:fs/promises`
* → `fs`), packages become their name (`@a/b/c` → `@a/b`), and relative paths are kept as is.
*/
function normalizeModule(spec) {
	if (spec.startsWith(".") || spec.startsWith("/")) return spec;
	const bare = spec.replace(/^node:/, "");
	const base = bare.split("/")[0] ?? bare;
	if (BUILTINS.has(bare) || BUILTINS.has(base)) return base;
	const segs = bare.split("/");
	return bare.startsWith("@") ? segs.slice(0, 2).join("/") : segs[0] ?? bare;
}
/** True when the normalized name is a Node.js builtin module. */
function isBuiltin(name) {
	return BUILTINS.has(name);
}
/** The static string value of a node: string literals, template literals without expressions, and `+` of those. */
function staticString(node, scope) {
	if (!node) return void 0;
	switch (node.type) {
		case "Literal": return typeof node.value === "string" ? node.value : void 0;
		case "TemplateLiteral": return node.expressions.length === 0 ? node.quasis[0]?.value.cooked ?? void 0 : void 0;
		case "BinaryExpression": {
			if (node.operator !== "+") return void 0;
			const l = staticString(node.left, scope);
			const r = l === void 0 ? void 0 : staticString(node.right, scope);
			return l !== void 0 && r !== void 0 ? l + r : void 0;
		}
		case "Identifier": {
			const b = scope?.bindings.get(node.name);
			return b?.kind === "string" ? b.value : void 0;
		}
		case "ParenthesizedExpression": return staticString(node.expression, scope);
		default: return;
	}
}
/** A member expression's property name, when it is static (`a.b`, `a["b"]`). */
function propName(node) {
	if (!node.computed) return node.property.type === "Identifier" ? node.property.name : void 0;
	return staticString(node.property);
}
/** Strips parentheses, `await`, and optional chaining wrappers. */
function unwrap(node) {
	let n = node;
	for (;;) if (n.type === "ParenthesizedExpression" || n.type === "ChainExpression") n = n.expression;
	else if (n.type === "AwaitExpression") n = n.argument;
	else return n;
}
/** True for `require` or a name bound to it. */
function isRequireCallee(node, scope) {
	return node.type === "Identifier" && (node.name === "require" || scope.bindings.get(node.name)?.kind === "require");
}
/** True for `process.env` and `globalThis.process.env` (and `global.`). */
function isProcessEnv(node) {
	if (node.type !== "MemberExpression" || propName(node) !== "env") return false;
	const obj = node.object;
	if (obj.type === "Identifier") return obj.name === "process";
	return obj.type === "MemberExpression" && propName(obj) === "process" && obj.object.type === "Identifier" && (obj.object.name === "globalThis" || obj.object.name === "global");
}
/** Resolves an expression to the module (and first member) it refers to, if any. */
function resolveModule(node, scope) {
	const n = unwrap(node);
	if (n.type === "CallExpression" && isRequireCallee(n.callee, scope)) {
		const spec = staticString(n.arguments[0], scope);
		return spec === void 0 ? void 0 : { module: normalizeModule(spec) };
	}
	if (n.type === "ImportExpression") {
		const spec = staticString(n.source, scope);
		return spec === void 0 ? void 0 : { module: normalizeModule(spec) };
	}
	if (n.type === "Identifier") {
		const b = scope.bindings.get(n.name);
		return b?.kind === "module" ? b.member === void 0 ? { module: b.module } : {
			module: b.module,
			member: b.member
		} : void 0;
	}
	if (n.type === "MemberExpression") {
		const base = resolveModule(n.object, scope);
		if (!base) return void 0;
		if (base.member !== void 0) return base;
		const member = propName(n);
		return member === void 0 ? base : {
			module: base.module,
			member
		};
	}
}
function bind(scope, name, b) {
	if (!scope.bindings.has(name)) scope.bindings.set(name, b);
}
function bindPattern(scope, id, init) {
	if (!init) return;
	const value = unwrap(init);
	if (id.type === "Identifier") {
		if (value.type === "Identifier" && isRequireCallee(value, scope)) return bind(scope, id.name, { kind: "require" });
		if (isProcessEnv(value)) return bind(scope, id.name, { kind: "env" });
		const str = staticString(value, scope);
		if (str !== void 0) return bind(scope, id.name, {
			kind: "string",
			value: str
		});
		const mod = resolveModule(value, scope);
		if (mod) bind(scope, id.name, {
			kind: "module",
			...mod
		});
		return;
	}
	if (id.type !== "ObjectPattern") return;
	const mod = resolveModule(value, scope);
	if (!mod) return;
	for (const p of id.properties) {
		if (p.type !== "Property") continue;
		const key = p.computed ? staticString(p.key) : p.key.type === "Identifier" ? p.key.name : staticString(p.key);
		const target = p.value.type === "AssignmentPattern" ? p.value.left : p.value;
		if (key === void 0 || target.type !== "Identifier") continue;
		bind(scope, target.name, {
			kind: "module",
			module: mod.module,
			member: mod.member ?? key
		});
	}
}
function declarePattern(scope, p) {
	if (!p) return;
	switch (p.type) {
		case "Identifier":
			scope.declared.add(p.name);
			break;
		case "ObjectPattern":
			for (const prop of p.properties) declarePattern(scope, prop.type === "Property" ? prop.value : prop.argument);
			break;
		case "ArrayPattern":
			for (const el of p.elements) declarePattern(scope, el);
			break;
		case "RestElement":
			declarePattern(scope, p.argument);
			break;
		case "AssignmentPattern": declarePattern(scope, p.left);
	}
}
/** Runs the binding pass over a parsed program. */
function collectScope(program) {
	const scope = {
		bindings: /* @__PURE__ */ new Map(),
		declared: /* @__PURE__ */ new Set()
	};
	full(program, (node) => {
		switch (node.type) {
			case "VariableDeclarator":
				declarePattern(scope, node.id);
				bindPattern(scope, node.id, node.init);
				break;
			case "AssignmentExpression":
				if (node.operator === "=" && node.left.type === "Identifier") bindPattern(scope, node.left, node.right);
				break;
			case "FunctionDeclaration":
			case "FunctionExpression":
			case "ArrowFunctionExpression":
				if (node.type !== "ArrowFunctionExpression" && node.id) scope.declared.add(node.id.name);
				for (const p of node.params) declarePattern(scope, p);
				break;
			case "ClassDeclaration":
			case "ClassExpression":
				if (node.id) scope.declared.add(node.id.name);
				break;
			case "CatchClause":
				declarePattern(scope, node.param);
				break;
			case "ImportDeclaration": {
				const module = normalizeModule(String(node.source.value));
				for (const s of node.specifiers) {
					scope.declared.add(s.local.name);
					if (s.type === "ImportSpecifier") {
						const imported = s.imported.type === "Identifier" ? s.imported.name : String(s.imported.value);
						bind(scope, s.local.name, imported === "default" ? {
							kind: "module",
							module
						} : {
							kind: "module",
							module,
							member: imported
						});
					} else bind(scope, s.local.name, {
						kind: "module",
						module
					});
				}
				break;
			}
		}
	});
	return scope;
}
var BUILTINS;
var init_bindings = __esmMin((() => {
	init_walk();
	BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/, "")));
}));
// ../packages/analyzer/src/ast.ts
/** Calls `cb` on every node under `root`, not descending into nested functions. */
function shallow(root, cb, parent) {
	cb(root, parent);
	for (const [key, value] of Object.entries(root)) {
		if (key === "loc") continue;
		const children = Array.isArray(value) ? value : [value];
		for (const c of children) if (c && typeof c === "object" && typeof c.type === "string" && !isFunction(c)) shallow(c, cb, root);
	}
}
function identifiersIn(nodes) {
	const out = /* @__PURE__ */ new Set();
	for (const n of nodes) shallow(n, (c) => c.type === "Identifier" && out.add(c.name));
	return out;
}
/** Dotted name of a simple callee such as `Object.keys` or `fetch`. */
function calleeName(n) {
	if (n.type === "Identifier") return n.name;
	if (n.type === "MemberExpression" && n.object.type === "Identifier") {
		const p = propName(n);
		return p === void 0 ? void 0 : `${n.object.name}.${p}`;
	}
}
function propNameOf(n) {
	if (n.type === "Identifier") return n.name;
	return n.type === "Literal" && typeof n.value === "string" ? n.value : void 0;
}
/** A string literal, a template literal, or a `+` concatenation involving one. */
function stringish(n) {
	if (!n) return false;
	if (n.type === "Literal") return typeof n.value === "string";
	if (n.type === "TemplateLiteral") return true;
	return n.type === "BinaryExpression" && n.operator === "+" && (stringish(n.left) || stringish(n.right));
}
/** The identifier at the root of a member chain (`req` in `req.socket.write`), if any. */
function rootIdentifier(n) {
	let o = n;
	for (let depth = 0; depth < 20 && o.type === "MemberExpression"; depth++) o = o.object;
	return o.type === "Identifier" ? o.name : void 0;
}
var lineOf, isFunction, contains;
var init_ast = __esmMin((() => {
	init_bindings();
	lineOf = (n) => n.loc?.start.line ?? 0;
	isFunction = (n) => n.type === "FunctionDeclaration" || n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression";
	contains = (outer, inner) => inner.start >= outer.start && inner.end <= outer.end;
}));
// ../packages/analyzer/src/tables.ts
var MODULE_CAPS, HTTP_CLIENTS, NATIVE_LOADERS, NET_MODULES, GLOBAL_NET, GLOBAL_OBJECTS, ENUMERATORS, WRITE_FNS, BINDING_CAPS, DECODE_ENCODINGS, HEX_ID;
var init_tables = __esmMin((() => {
	MODULE_CAPS = {
		fs: "fs",
		http: "net",
		https: "net",
		http2: "net",
		net: "net",
		tls: "net",
		dgram: "net",
		dns: "net",
		child_process: "child_process",
		vm: "dynamic_code",
		worker_threads: "worker",
		cluster: "worker",
		crypto: "crypto",
		os: "os_info"
	};
	HTTP_CLIENTS = /* @__PURE__ */ new Set([
		"node-fetch",
		"axios",
		"got",
		"undici",
		"request",
		"superagent",
		"needle",
		"phin",
		"ky",
		"ofetch",
		"cross-fetch",
		"isomorphic-fetch",
		"ws",
		"socket.io-client",
		"make-fetch-happen",
		"minipass-fetch"
	]);
	NATIVE_LOADERS = /* @__PURE__ */ new Set([
		"bindings",
		"node-gyp-build",
		"node-gyp-build-optional-packages",
		"@mapbox/node-pre-gyp"
	]);
	NET_MODULES = /* @__PURE__ */ new Set([...Object.keys(MODULE_CAPS).filter((m) => MODULE_CAPS[m] === "net"), ...HTTP_CLIENTS]);
	GLOBAL_NET = /* @__PURE__ */ new Set([
		"fetch",
		"WebSocket",
		"XMLHttpRequest",
		"EventSource"
	]);
	GLOBAL_OBJECTS = /* @__PURE__ */ new Set([
		"globalThis",
		"global",
		"window",
		"self"
	]);
	ENUMERATORS = /* @__PURE__ */ new Set([
		"Object.keys",
		"Object.values",
		"Object.entries",
		"Object.getOwnPropertyNames",
		"Object.assign",
		"JSON.stringify"
	]);
	WRITE_FNS = /* @__PURE__ */ new Set([
		"writeFile",
		"writeFileSync",
		"appendFile",
		"appendFileSync",
		"write",
		"writeSync"
	]);
	BINDING_CAPS = {
		fs: "fs",
		spawn_sync: "child_process",
		process_wrap: "child_process",
		tcp_wrap: "net",
		udp_wrap: "net",
		tls_wrap: "net",
		cares_wrap: "net"
	};
	DECODE_ENCODINGS = /* @__PURE__ */ new Set([
		"base64",
		"base64url",
		"hex"
	]);
	HEX_ID = /^_0x[0-9a-f]{4,}$/i;
}));
// ../packages/analyzer/src/flow.ts
/**
* True for a call or `new` that talks to the network: a net builtin or known HTTP client
* (`https.get`, `axios.post`, `require("https").request`), global `fetch`, or
* `new WebSocket` / `XMLHttpRequest` / `EventSource` (also via `globalThis.`).
*/
function isNetCallNode(n, scope) {
	if (n.type !== "CallExpression" && n.type !== "NewExpression") return false;
	const callee = unwrap(n.callee);
	const mod = resolveModule(callee, scope);
	if (mod && NET_MODULES.has(mod.module)) return true;
	const isNew = n.type === "NewExpression";
	if (callee.type === "Identifier") return GLOBAL_NET.has(callee.name) && !scope.declared.has(callee.name) && (isNew || callee.name === "fetch");
	const [obj, prop] = (calleeName(callee) ?? "").split(".");
	return obj !== void 0 && GLOBAL_OBJECTS.has(obj) && prop !== void 0 && GLOBAL_NET.has(prop);
}
/** True for `https.request(o).end`-style callees: a member chain built on a network call. */
function callsNetObject(callee, scope) {
	let o = callee;
	for (let depth = 0; depth < 20; depth++) if (o.type === "MemberExpression") o = unwrap(o.object);
	else if (o.type === "CallExpression") {
		if (isNetCallNode(o, scope)) return true;
		o = unwrap(o.callee);
	} else return false;
	return false;
}
/** True when a value assigned to `name` flows (through variable assignments) into one of `sinks`. */
function reaches(name, edges, sinks) {
	const tainted = /* @__PURE__ */ new Set([name]);
	for (let changed = true; changed;) {
		changed = false;
		for (const e of edges) if (!tainted.has(e.to) && [...e.from].some((x) => tainted.has(x))) {
			tainted.add(e.to);
			changed = true;
		}
	}
	return sinks.some((s) => [...s].some((x) => tainted.has(x)));
}
/** `anc` is the ancestor chain ending with `node`. */
function valueFlow(node, anc, scope) {
	let direct = false;
	const viaObjects = [];
	let flow;
	for (let i = anc.length - 2; i >= 0 && !direct; i--) {
		const a = anc[i];
		if (!a || isFunction(a)) break;
		if ((a.type === "CallExpression" || a.type === "NewExpression") && a.arguments.some((x) => contains(x, node))) {
			const callee = unwrap(a.callee);
			if (isNetCallNode(a, scope) || callsNetObject(callee, scope)) direct = true;
			else if (callee.type === "MemberExpression") {
				const root = rootIdentifier(callee);
				if (root !== void 0) viaObjects.push(root);
			}
		}
		if (a.type === "VariableDeclarator" && a.id.type === "Identifier") flow ??= a.id.name;
		if (a.type === "AssignmentExpression" && a.left.type === "Identifier") flow ??= a.left.name;
		if (a.type === "ForInStatement" && a.left.type === "VariableDeclaration") {
			const id = a.left.declarations[0]?.id;
			if (id?.type === "Identifier") flow ??= id.name;
		}
	}
	return flow === void 0 ? {
		direct,
		viaObjects
	} : {
		direct,
		viaObjects,
		flow
	};
}
var init_flow = __esmMin((() => {
	init_ast();
	init_bindings();
	init_tables();
}));
// ../packages/analyzer/src/scope.ts
/** Adds the identifiers a binding pattern declares (`{ a, b: [c, ...d] = x }` → a, c, d). */
function patternNames(p, out) {
	if (!p) return;
	switch (p.type) {
		case "Identifier":
			out.add(p.name);
			return;
		case "ObjectPattern":
			for (const prop of p.properties) patternNames(prop.type === "RestElement" ? prop.argument : prop.value, out);
			return;
		case "ArrayPattern":
			for (const el of p.elements) patternNames(el, out);
			return;
		case "RestElement":
			patternNames(p.argument, out);
			return;
		case "AssignmentPattern":
			patternNames(p.left, out);
			return;
		default: return;
	}
}
/**
* `var` declarations and function declarations anywhere in a function body except
* nested functions (both hoist to the function; block functions also hoist in sloppy
* mode). Only statement positions can declare, so expression trees are never walked,
* which keeps this cheap on minified bundles.
*/
function hoistedNames(n, out) {
	if (!n) return;
	switch (n.type) {
		case "VariableDeclaration":
			if (n.kind === "var") for (const d of n.declarations) patternNames(d.id, out);
			return;
		case "FunctionDeclaration":
			if (n.id) out.add(n.id.name);
			return;
		case "BlockStatement":
			for (const s of n.body) hoistedNames(s, out);
			return;
		case "IfStatement":
			hoistedNames(n.consequent, out);
			hoistedNames(n.alternate, out);
			return;
		case "ForStatement":
			if (n.init?.type === "VariableDeclaration") hoistedNames(n.init, out);
			hoistedNames(n.body, out);
			return;
		case "ForInStatement":
		case "ForOfStatement":
			if (n.left.type === "VariableDeclaration") hoistedNames(n.left, out);
			hoistedNames(n.body, out);
			return;
		case "WhileStatement":
		case "DoWhileStatement":
		case "LabeledStatement":
		case "WithStatement":
			hoistedNames(n.body, out);
			return;
		case "TryStatement":
			hoistedNames(n.block, out);
			hoistedNames(n.handler?.body, out);
			hoistedNames(n.finalizer, out);
			return;
		case "SwitchStatement":
			for (const c of n.cases) for (const s of c.consequent) hoistedNames(s, out);
			return;
		case "ExportNamedDeclaration":
			hoistedNames(n.declaration, out);
			return;
		case "ExportDefaultDeclaration":
			if (n.declaration.type === "FunctionDeclaration") hoistedNames(n.declaration, out);
			return;
		default: return;
	}
}
/** `let` / `const` / `class` / function declarations directly in a statement list. */
function lexicalNames(statements, out) {
	for (const raw of statements) {
		let s = raw;
		if (s.type === "ExportNamedDeclaration") s = s.declaration;
		else if (s.type === "ExportDefaultDeclaration") s = s.declaration;
		if (!s) continue;
		if (s.type === "VariableDeclaration" && s.kind !== "var") for (const d of s.declarations) patternNames(d.id, out);
		else if ((s.type === "ClassDeclaration" || s.type === "FunctionDeclaration") && s.id) out.add(s.id.name);
	}
}
/**
* The names `n` declares if it opens a scope, else `null`. `parent` tells a function's
* own body block (part of the function's scope) from a nested block.
*/
function scopeNames(n, parent) {
	const out = /* @__PURE__ */ new Set();
	switch (n.type) {
		case "Program":
			for (const s of n.body) hoistedNames(s, out);
			lexicalNames(n.body, out);
			return out;
		case "FunctionDeclaration":
		case "FunctionExpression":
		case "ArrowFunctionExpression":
			for (const p of n.params) patternNames(p, out);
			if (n.type === "FunctionExpression" && n.id) out.add(n.id.name);
			if (n.body.type === "BlockStatement") {
				hoistedNames(n.body, out);
				lexicalNames(n.body.body, out);
			}
			return out;
		case "BlockStatement":
			if (parent && isFunction(parent)) return null;
			lexicalNames(n.body, out);
			return out;
		case "StaticBlock":
			hoistedNames({
				type: "BlockStatement",
				body: n.body
			}, out);
			lexicalNames(n.body, out);
			return out;
		case "ForStatement":
			if (n.init?.type === "VariableDeclaration" && n.init.kind !== "var") for (const d of n.init.declarations) patternNames(d.id, out);
			return out;
		case "ForInStatement":
		case "ForOfStatement":
			if (n.left.type === "VariableDeclaration" && n.left.kind !== "var") for (const d of n.left.declarations) patternNames(d.id, out);
			return out;
		case "CatchClause":
			patternNames(n.param, out);
			return out;
		case "SwitchStatement":
			for (const c of n.cases) lexicalNames(c.consequent, out);
			return out;
		default: return null;
	}
}
var EMPTY, Scopes;
var init_scope = __esmMin((() => {
	init_ast();
	EMPTY = {
		ids: [],
		names: []
	};
	Scopes = class Scopes {
		chains = /* @__PURE__ */ new WeakMap();
		notScopes = /* @__PURE__ */ new WeakSet();
		nextId = 0;
		/** The scope chain at the end of `anc` (an ancestor chain, outermost first). */
		chain(anc) {
			for (let i = anc.length - 1; i >= 0; i--) {
				const n = anc[i];
				const hit = this.chains.get(n);
				if (hit) return hit;
				if (this.notScopes.has(n)) continue;
				const names = scopeNames(n, anc[i - 1]);
				if (names === null || names.size === 0 && n.type !== "Program") {
					this.notScopes.add(n);
					continue;
				}
				const outer = i === 0 ? EMPTY : this.chain(anc.slice(0, i));
				const chain = {
					ids: [this.nextId++, ...outer.ids],
					names: [names, ...outer.names]
				};
				this.chains.set(n, chain);
				return chain;
			}
			return EMPTY;
		}
		/**
		* `name` qualified by the innermost scope in `chain` that declares it. Undeclared
		* names (globals, implicit globals) share one file-wide scope.
		*/
		static resolve(name, chain) {
			for (let i = 0; i < chain.names.length; i++) if (chain.names[i]?.has(name)) return `${chain.ids[i]}:${name}`;
			return `g:${name}`;
		}
		/** {@link Scopes.resolve} for every name in `names`. */
		static resolveAll(names, chain) {
			const out = /* @__PURE__ */ new Set();
			for (const n of names) out.add(Scopes.resolve(n, chain));
			return out;
		}
		/** `name` as seen from the end of `anc`. */
		qualify(name, anc) {
			return Scopes.resolve(name, this.chain(anc));
		}
		/** Every name in `names` as seen from the end of `anc`. */
		qualifyAll(names, anc) {
			return Scopes.resolveAll(names, this.chain(anc));
		}
	};
}));
// ../packages/analyzer/src/visit.ts
/** Runs both passes over one parsed program. */
function analyzeProgram(program) {
	const v = new Visitor(collectScope(program));
	fullAncestor(program, (node, _st, ancestors, type) => v.visit(node, ancestors, type));
	return v.finish();
}
var Visitor;
var init_visit = __esmMin((() => {
	init_walk();
	init_bindings();
	init_text();
	init_flow();
	init_ast();
	init_scope();
	init_tables();
	Visitor = class {
		scope;
		/** Qualifies flow names by declaring scope, so minified `e`s in different functions don't merge. */
		scopes = new Scopes();
		facts = {
			uses: [],
			envKeys: [],
			envSensitive: [],
			envExfil: [],
			sensitivePaths: [],
			endpoints: [],
			rawIp: [],
			obfuscation: [],
			encodedPayloads: [],
			highEntropy: [],
			localImports: []
		};
		ids = 0;
		hexIds = 0;
		escapes = 0;
		stringChars = 0;
		platformLines = [];
		rotations = [];
		parseIntFns = /* @__PURE__ */ new Set();
		decodes = [];
		sinks = [];
		edges = [];
		envSources = [];
		netSinks = [];
		netObjects = /* @__PURE__ */ new Set();
		objectCalls = [];
		constructor(scope) {
			this.scope = scope;
		}
		global(name) {
			return !this.scope.declared.has(name);
		}
		use(cap, node, evidence) {
			this.facts.uses.push({
				cap,
				line: lineOf(node),
				evidence: clean(evidence, 80)
			});
		}
		visit(node, anc, type) {
			const parent = anc[anc.length - 2];
			switch (node.type) {
				case "Identifier": return this.identifier(node, anc, parent, type);
				case "MemberExpression": return this.member(node, anc);
				case "CallExpression":
				case "NewExpression": return this.call(node, anc);
				case "ImportDeclaration":
					this.importSpec(String(node.source.value), node, `import "${String(node.source.value)}"`);
					if (node.specifiers.some((s) => s.type === "ImportSpecifier" && propNameOf(s.imported) === "createRequire") && normalizeModule(String(node.source.value)) === "module") this.use("dynamic_require", node, "createRequire");
					return;
				case "ExportNamedDeclaration":
				case "ExportAllDeclaration":
					if (node.source) this.importSpec(String(node.source.value), node, `export from "${String(node.source.value)}"`);
					return;
				case "ImportExpression": {
					const spec = staticString(node.source, this.scope);
					if (spec === void 0) this.use("dynamic_require", node, "import(<expression>)");
					else this.importSpec(spec, node, `import("${spec}")`);
					return;
				}
				case "Literal":
					if (typeof node.value === "string") this.string(node.value, node.raw ?? "", node, parent);
					return;
				case "TemplateLiteral":
					for (const q of node.quasis) this.string(q.value.cooked ?? "", q.value.raw, q, parent, node);
					return;
				case "VariableDeclarator":
					if (node.id.type === "Identifier" && node.init) this.assigned(node.id.name, node.init, anc);
					return;
				case "AssignmentExpression":
					if (node.left.type === "Identifier") this.assigned(node.left.name, node.right, anc);
					return;
				default: return;
			}
		}
		assigned(name, value, anc) {
			const to = this.scopes.qualify(name, anc);
			this.edges.push({
				to,
				from: this.scopes.qualifyAll(identifiersIn([value]), anc)
			});
			if (this.isNetCallNode(unwrap(value))) this.netObjects.add(to);
		}
		identifier(node, anc, parent, type) {
			this.ids++;
			if (HEX_ID.test(node.name)) this.hexIds++;
			if (type === "VariablePattern") return;
			const name = node.name;
			if (GLOBAL_NET.has(name) && this.global(name)) this.use("net", node, name);
			if (name === "eval" && this.global(name)) this.use("dynamic_code", node, "eval");
			if (this.scope.bindings.get(name)?.kind === "env" && parent) this.env(node, anc, name);
		}
		member(node, anc) {
			if (isProcessEnv(node)) return this.env(node, anc, "process.env");
			const prop = propName(node);
			if (prop === void 0) return;
			const obj = node.object;
			if (obj.type === "Identifier") {
				if (GLOBAL_OBJECTS.has(obj.name) && GLOBAL_NET.has(prop)) this.use("net", node, `${obj.name}.${prop}`);
				if (GLOBAL_OBJECTS.has(obj.name) && prop === "eval") this.use("dynamic_code", node, `${obj.name}.eval`);
				if (obj.name === "process" && (prop === "platform" || prop === "arch")) this.platformLines.push(lineOf(node));
				if (obj.name === "process" && prop === "dlopen") this.use("native_addon", node, "process.dlopen");
				if (obj.name === "module" && prop === "require") this.use("dynamic_require", node, "module.require");
			}
			if (prop === "createRequire" && resolveModule(obj, this.scope)?.module === "module") this.use("dynamic_require", node, "createRequire");
		}
		call(node, anc) {
			const callee = unwrap(node.callee);
			const args = node.arguments;
			const name = calleeName(callee);
			const isNew = node.type === "NewExpression";
			if (!isNew && isRequireCallee(callee, this.scope)) {
				const spec = staticString(args[0], this.scope);
				if (spec === void 0) this.use("dynamic_require", node, `${name ?? "require"}(<expression>)`);
				else this.importSpec(spec, node, `require("${spec}")`);
			}
			const mod = resolveModule(callee, this.scope);
			if (!isNew && mod?.module === "module" && mod.member === "createRequire") this.use("dynamic_require", node, "createRequire()");
			if (name === "process.binding" || name === "process._linkedBinding") {
				const which = staticString(args[0], this.scope);
				const cap = which === void 0 ? void 0 : BINDING_CAPS[which];
				if (cap) this.use(cap, node, `process.binding("${which}")`);
			}
			if (name === "Function" && this.global("Function") || name === "globalThis.Function") this.use("dynamic_code", node, isNew ? "new Function()" : "Function()");
			if (!isNew && (name === "setTimeout" || name === "setInterval") && this.global(name) && stringish(args[0])) this.use("dynamic_code", node, `${name}(<string>)`);
			if (!isNew && callee.type === "MemberExpression" && propName(callee) === "constructor" && staticString(args[0], this.scope) !== void 0) this.use("dynamic_code", node, ".constructor(<string>)");
			if (name === "parseInt") {
				for (const a of anc) if (isFunction(a)) this.parseIntFns.add(a);
			}
			this.rotation(node, callee, args, anc);
			const isNet = this.isNetCallNode(node);
			if (isNet) this.rawIps(node, args);
			if (isNet || this.callsNetObject(callee)) this.netSinks.push(this.scopes.qualifyAll(identifiersIn(args), anc));
			else if (callee.type === "MemberExpression") {
				const root = rootIdentifier(callee);
				if (root !== void 0) {
					const chain = this.scopes.chain(anc);
					this.objectCalls.push({
						obj: Scopes.resolve(root, chain),
						idents: identifiersIn(args),
						chain
					});
				}
			}
			this.decode(node, name, args, anc);
			if (this.isSink(node)) this.sinks.push(this.scopes.qualifyAll(identifiersIn(args), anc));
		}
		importSpec(spec, node, evidence) {
			if (spec.startsWith(".") || spec.startsWith("/")) {
				this.facts.localImports.push(spec);
				if (/\.node$/i.test(spec)) this.use("native_addon", node, evidence);
				return;
			}
			const m = normalizeModule(spec);
			const cap = isBuiltin(m) ? MODULE_CAPS[m] : void 0;
			if (cap) this.use(cap, node, evidence);
			if (NATIVE_LOADERS.has(m)) this.use("native_addon", node, evidence);
			if (HTTP_CLIENTS.has(m)) this.use("net", node, evidence);
		}
		/** `node` is `process.env` or a name bound to it. */
		env(node, anc, label) {
			const parent = anc[anc.length - 2];
			const grand = anc[anc.length - 3];
			if (parent?.type === "MemberExpression" && parent.object === node) {
				const key = propName(parent);
				if (key === void 0) return this.use("env", parent, `${label}[<expression>]`);
				return grand?.type === "AssignmentExpression" && grand.left === parent || grand?.type === "UnaryExpression" && grand.operator === "delete" ? this.use("env", parent, `${label}.${key} (write)`) : this.envRead(key, parent, anc.slice(0, -1));
			}
			if (parent?.type === "VariableDeclarator" && parent.init === node && parent.id.type === "ObjectPattern") return this.envPattern(parent.id, anc);
			if (parent?.type === "AssignmentExpression" && parent.right === node && parent.left.type === "ObjectPattern") return this.envPattern(parent.left, anc);
			if (parent?.type === "SpreadElement") return this.enumerate(node, `...${label}`, anc);
			if (parent?.type === "ForInStatement" && parent.right === node) return this.enumerate(node, `for…in ${label}`, anc);
			if (parent?.type === "CallExpression" && parent.arguments.includes(node)) {
				const fn = calleeName(unwrap(parent.callee));
				if (fn === "Object.assign" && parent.arguments[0] === node) return this.use("env", node, `Object.assign(${label}, …) (write)`);
				if (fn !== void 0 && ENUMERATORS.has(fn)) return this.enumerate(node, `${fn}(${label})`, anc);
			}
			if (label === "process.env") this.use("env", node, label);
		}
		/** `anc` ends with `node` for expression reads; destructuring passes `taint` (the target name) instead. */
		envRead(key, node, anc, taint, scopeAnc) {
			this.facts.envKeys.push(key);
			this.use("env", node, `process.env.${key}`);
			if (isSensitiveEnvKey(key)) this.sensitive(node, clean(`reads process.env.${key}`, 100), anc, taint, scopeAnc ?? anc ?? []);
		}
		/** Records a sensitive env value and where it flows: into a network call, an object method, or a variable. */
		/** `scopeAnc` locates the source for scope resolution (destructuring passes the `process.env` chain). */
		sensitive(node, detail, anc, taint, scopeAnc = anc ?? []) {
			const line = lineOf(node);
			this.facts.envSensitive.push({
				line,
				detail
			});
			const { direct, viaObjects, flow } = valueFlow(node, anc ?? [], this.scope);
			const target = taint ?? flow;
			this.envSources.push({
				line,
				detail,
				direct,
				viaObjects: viaObjects.map((o) => this.scopes.qualify(o, scopeAnc)),
				...target === void 0 ? {} : { taint: this.scopes.qualify(target, scopeAnc) }
			});
		}
		/** `anc` is the ancestor chain of the `process.env` node being destructured. */
		envPattern(p, anc) {
			for (const prop of p.properties) if (prop.type === "RestElement") this.enumerate(prop, "rest destructuring of process.env", void 0, prop.argument.type === "Identifier" ? prop.argument.name : void 0, anc);
			else {
				const key = prop.computed ? staticString(prop.key, this.scope) : propNameOf(prop.key);
				const target = prop.value.type === "AssignmentPattern" ? prop.value.left : prop.value;
				if (key !== void 0) this.envRead(key, prop, void 0, target.type === "Identifier" ? target.name : void 0, anc);
				else this.use("env", prop, "process.env[<expression>]");
			}
		}
		enumerate(node, how, anc, taint, scopeAnc) {
			this.use("env", node, how);
			this.sensitive(node, clean(`enumerates process.env (${how})`, 100), anc, taint, scopeAnc ?? anc ?? []);
		}
		string(value, raw, node, parent, self = node) {
			if (value.length === 0) return;
			this.stringChars += value.length;
			this.escapes += countAsciiEscapes(raw);
			const line = lineOf(node);
			const what = sensitivePath(value);
			if (what) this.facts.sensitivePaths.push({
				line,
				snippet: clean(value),
				detail: what
			});
			const hostContext = parent?.type === "Property" && parent.value === self && ["host", "hostname"].includes(propNameOf(parent.key) ?? "");
			for (const ep of findEndpoints(value, hostContext)) this.facts.endpoints.push({
				...ep,
				line
			});
			if (value.length > 200) {
				const h = shannonEntropy(value);
				if (h > 5.2) this.facts.highEntropy.push({
					line,
					snippet: clean(value, 60),
					detail: `${value.length} chars, entropy ${h.toFixed(2)}`
				});
			}
		}
		isNetCallNode(n) {
			return isNetCallNode(n, this.scope);
		}
		callsNetObject(callee) {
			return callsNetObject(callee, this.scope);
		}
		rawIps(node, args) {
			for (const arg of args) shallow(arg, (n, parent) => {
				const s = n.type === "Literal" || n.type === "Identifier" || n.type === "TemplateLiteral" ? staticString(n, this.scope) : void 0;
				if (s === void 0) return;
				const hostCtx = parent?.type === "Property" && ["host", "hostname"].includes(propNameOf(parent.key) ?? "");
				for (const ep of findEndpoints(s, hostCtx)) if (ep.ip) this.facts.rawIp.push({
					line: lineOf(node),
					snippet: clean(ep.endpoint)
				});
			});
		}
		decode(node, name, args, anc) {
			const isBufferFrom = name === "Buffer.from" || node.type === "NewExpression" && name === "Buffer";
			const isAtob = node.type === "CallExpression" && (name === "atob" || name === "globalThis.atob");
			if (!isBufferFrom && !isAtob) return;
			if (isBufferFrom && !DECODE_ENCODINGS.has(staticString(args[1], this.scope) ?? "")) return;
			const blob = staticString(args[0], this.scope);
			if (blob === void 0 || !isEncodedBlob(blob)) return;
			let inSink = false;
			let taint;
			for (let i = anc.length - 2; i >= 0; i--) {
				const a = anc[i];
				if (!a || isFunction(a)) break;
				if ((a.type === "CallExpression" || a.type === "NewExpression") && this.isSink(a) && a.arguments.some((x) => contains(x, node))) {
					inSink = true;
					break;
				}
				if (a.type === "VariableDeclarator" && a.id.type === "Identifier") taint ??= a.id.name;
				if (a.type === "AssignmentExpression" && a.left.type === "Identifier") taint ??= a.left.name;
			}
			if (taint !== void 0) taint = this.scopes.qualify(taint, anc);
			this.decodes.push({
				line: lineOf(node),
				inSink,
				...taint === void 0 ? {} : { taint },
				snippet: `${name ?? "decode"}(<${blob.length}-char literal>)`
			});
		}
		isSink(call) {
			if (call.type !== "CallExpression" && call.type !== "NewExpression") return false;
			const callee = unwrap(call.callee);
			if (callee.type === "Identifier" && (callee.name === "eval" || callee.name === "Function") && this.global(callee.name)) return true;
			const mod = resolveModule(callee, this.scope);
			if (mod?.module === "vm") return true;
			const fn = callee.type === "Identifier" ? mod?.member ?? callee.name : callee.type === "MemberExpression" ? propName(callee) : void 0;
			return fn !== void 0 && (WRITE_FNS.has(fn) || fn === "_compile");
		}
		rotation(node, callee, args, anc) {
			if (node.type !== "CallExpression" || callee.type !== "MemberExpression" || propName(callee) !== "push") return;
			const arr = callee.object;
			const inner = args[0] ? unwrap(args[0]) : void 0;
			if (arr.type !== "Identifier" || inner?.type !== "CallExpression") return;
			const ic = unwrap(inner.callee);
			if (ic.type !== "MemberExpression" || propName(ic) !== "shift" || ic.object.type !== "Identifier" || ic.object.name !== arr.name) return;
			const fn = anc.findLast(isFunction) ?? anc[0];
			const inLoop = anc.some((a) => a.type === "WhileStatement" || a.type === "DoWhileStatement" || a.type === "ForStatement");
			if (fn) this.rotations.push({
				fn,
				inLoop
			});
		}
		finish() {
			const f = this.facts;
			if (this.rotations.some((r) => r.inLoop && this.parseIntFns.has(r.fn))) f.obfuscation.push("string-array rotation (push/shift loop with parseInt)");
			if (this.ids >= 10 && this.hexIds / this.ids > .3) f.obfuscation.push(`${Math.round(100 * this.hexIds / this.ids)}% of identifiers look like _0x…`);
			if (this.escapes >= 32 && this.escapes / Math.max(1, this.stringChars) >= .3) f.obfuscation.push(`${this.escapes} \\x/\\u escapes of printable ASCII in string literals`);
			for (const d of this.decodes) if (d.inSink || d.taint !== void 0 && reaches(d.taint, this.edges, this.sinks)) f.encodedPayloads.push({
				line: d.line,
				snippet: d.snippet,
				detail: "decoded and passed to eval, Function, vm, or a write call"
			});
			const netSinks = [...this.netSinks, ...this.objectCalls.filter((c) => this.netObjects.has(c.obj)).map((c) => Scopes.resolveAll(c.idents, c.chain))];
			for (const s of this.envSources) if (s.direct || s.viaObjects.some((o) => this.netObjects.has(o)) || s.taint !== void 0 && reaches(s.taint, this.edges, netSinks)) f.envExfil.push({
				line: s.line,
				detail: `${s.detail}, which flows into a network call`
			});
			if (f.uses.some((u) => u.cap === "net")) for (const line of this.platformLines) f.uses.push({
				cap: "os_info",
				line,
				evidence: "process.platform/arch with net"
			});
			return f;
		}
	};
}));
// ../packages/analyzer/src/analyze.ts
/**
* Statically profiles one package: its capabilities, risk signals, files, endpoints, and
* env keys. It never executes package code. Pass the output of `readTarball`.
*
* Throws a `DepwardError` with `LIMIT_EXCEEDED` (too many files) or `INVALID_ARCHIVE`
* (no readable `package.json` object at the package root).
*/
function analyzePackage(pkgFiles, opts = {}) {
	const maxFileBytes = opts.maxFileBytes ?? 5242880;
	const maxFiles = opts.maxFiles ?? 2e4;
	const maxUses = opts.maxUsesPerCapability ?? 100;
	const maxEvidence = opts.maxEvidence ?? 10;
	if (pkgFiles.files.length > maxFiles) throw new DepwardError("LIMIT_EXCEEDED", `package has more than ${maxFiles} files`);
	const byPath = new Map(pkgFiles.files.map((f) => [f.path, f]));
	const pkg = readPackageJson(byPath.get("package.json"));
	const signals = [];
	const add = (id, message, evidence) => {
		if (evidence.length > 0) signals.push(makeSignal(id, message, evidence, maxEvidence));
	};
	const uses = Object.fromEntries(CAPABILITIES.map((c) => [c, []]));
	const facts = /* @__PURE__ */ new Map();
	const files = [];
	const endpoints = /* @__PURE__ */ new Set();
	const envKeys = /* @__PURE__ */ new Set();
	const stats = {
		jsFiles: 0,
		parsed: 0,
		unparsed: 0,
		skipped: 0,
		bytes: pkgFiles.unpackedSize
	};
	const minified = [];
	for (const file of pkgFiles.files) {
		const c = classifyFile(file.path, file.data);
		const summary = {
			path: file.path,
			size: file.data.byteLength,
			kind: c.kind,
			sha256: sha256(file.data)
		};
		files.push(summary);
		if (c.kind === "source") stats.skipped++;
		if (c.kind === "native" || c.kind === "wasm") {
			add("native-binary", `ships a native binary (${c.format ?? c.kind})`, [{
				file: file.path,
				detail: c.format ?? c.kind
			}]);
			if (/\.node$/i.test(file.path)) uses.native_addon.push({
				file: file.path,
				evidence: ".node file"
			});
		}
		if (c.kind !== "js") continue;
		stats.jsFiles++;
		if (file.data.byteLength > maxFileBytes) {
			stats.unparsed++;
			add("oversized-file", "file is too large to analyze", [{
				file: file.path,
				detail: `${file.data.byteLength} bytes (limit ${maxFileBytes})`
			}]);
			continue;
		}
		const text = new TextDecoder().decode(file.data);
		summary.minified = looksMinified(file.path, text);
		summary.bundled = looksBundled(text);
		if (file.data.byteLength >= 512) minified.push(summary.minified);
		const result = analyzeText(text);
		if ("error" in result) {
			stats.unparsed++;
			add("unparseable-file", "JavaScript file could not be parsed", [{
				file: file.path,
				detail: clean(result.error)
			}]);
			continue;
		}
		stats.parsed++;
		const f = result.facts;
		facts.set(file.path, f);
		fileSignals(file.path, f, add);
		for (const u of f.uses) uses[u.cap].push({
			file: file.path,
			line: u.line,
			evidence: u.evidence
		});
		for (const k of f.envKeys) envKeys.add(k);
		for (const e of f.endpoints) endpoints.add(e.endpoint);
	}
	const pkgEndpoints = [];
	for (const [key, value] of Object.entries(pkg)) {
		if (PKG_DOC_FIELDS.has(key)) continue;
		forEachString(value, (s) => {
			for (const e of findEndpoints(s)) {
				endpoints.add(e.endpoint);
				pkgEndpoints.push({
					file: "package.json",
					snippet: clean(e.endpoint),
					detail: key
				});
			}
		});
	}
	add("hardcoded-endpoint", "contains hardcoded network endpoints", pkgEndpoints);
	const scripts = readInstallScripts(pkg, byPath.has("binding.gyp"));
	installSignals(scripts, byPath, facts, add);
	if (minified.length > 0 && minified.every(Boolean)) add("minified-only", "ships only minified code", [{ detail: `${minified.length} JS file(s), all minified` }]);
	return {
		name: typeof pkg["name"] === "string" ? pkg["name"] : "",
		version: typeof pkg["version"] === "string" ? pkg["version"] : "",
		scripts,
		capabilities: Object.fromEntries(CAPABILITIES.map((c) => [c, dedupeUses(uses[c], maxUses)])),
		signals: signals.toSorted(compareSignals),
		files,
		endpoints: [...endpoints].toSorted(cmp),
		envKeys: [...envKeys].toSorted(cmp),
		stats
	};
}
function fileSignals(file, f, add) {
	const ev = (hits) => hits.map((h) => withoutUndefined({
		file,
		line: h.line,
		snippet: h.snippet,
		detail: h.detail
	}));
	add("env-sensitive-read", "reads sensitive environment variables", ev(f.envSensitive));
	add("env-exfil-pattern", "sends sensitive environment variables over the network", ev(f.envExfil));
	add("fs-sensitive-path", "references credential, browser-profile, or wallet locations", ev(f.sensitivePaths));
	add("obfuscation", "code looks obfuscated", f.obfuscation.map((detail) => ({
		file,
		detail
	})));
	add("encoded-payload", "decodes a large encoded literal and executes or writes it", ev(f.encodedPayloads));
	add("high-entropy-string", "contains long high-entropy string literals", ev(f.highEntropy));
	add("hardcoded-endpoint", "contains hardcoded network endpoints", f.endpoints.map((e) => ({
		file,
		line: e.line,
		snippet: clean(e.endpoint)
	})));
	add("raw-ip-endpoint", "makes network calls to a raw IP address", ev(f.rawIp));
}
function installSignals(scripts, byPath, facts, add) {
	const hooks = INSTALL_HOOKS.filter((h) => scripts[h] !== void 0);
	add("install-script", `runs install scripts (${hooks.join(", ")})`, hooks.map((h) => ({
		file: "package.json",
		snippet: clean(scripts[h] ?? ""),
		detail: h
	})));
	const network = [];
	for (const h of hooks) {
		const script = scripts[h] ?? "";
		const why = scriptNetworkReason(script) ?? netReachableFrom(script, byPath, facts);
		if (why) network.push({
			file: "package.json",
			snippet: clean(script),
			detail: `${h}: ${why}`
		});
	}
	add("install-script-network", "an install script can reach the network", network);
}
/** Follows the JS files a script runs (and their relative imports) looking for `net`. */
function netReachableFrom(script, byPath, facts) {
	const has = (p) => byPath.has(p);
	const queue = scriptEntryWords(script).flatMap((w) => resolveLocal(".", w, has) ?? []);
	const seen = new Set(queue);
	while (queue.length > 0 && seen.size <= 500) {
		const path = queue.shift() ?? "";
		const f = facts.get(path);
		if (!f) continue;
		if (f.uses.some((u) => u.cap === "net")) return `runs ${clean(path, 80)}, which uses the network`;
		for (const spec of f.localImports) {
			const next = resolveLocal(posix.dirname(path), spec, has);
			if (next !== void 0 && !seen.has(next)) {
				seen.add(next);
				queue.push(next);
			}
		}
	}
}
function readPackageJson(file) {
	if (!file) throw new DepwardError("INVALID_ARCHIVE", "package has no package.json");
	let pkg;
	try {
		pkg = JSON.parse(new TextDecoder().decode(file.data));
	} catch (err) {
		throw new DepwardError("INVALID_ARCHIVE", "package.json is not valid JSON", { cause: err });
	}
	if (pkg === null || typeof pkg !== "object" || Array.isArray(pkg)) throw new DepwardError("INVALID_ARCHIVE", "package.json is not an object");
	return pkg;
}
function forEachString(value, cb, depth = 0) {
	if (depth > 20) return;
	if (typeof value === "string") cb(value);
	else if (Array.isArray(value)) for (const v of value) forEachString(v, cb, depth + 1);
	else if (value !== null && typeof value === "object") for (const v of Object.values(value)) forEachString(v, cb, depth + 1);
}
function dedupeUses(list, max) {
	const seen = /* @__PURE__ */ new Set();
	const out = [];
	const sorted = list.toSorted((a, b) => cmp(a.file, b.file) || (a.line ?? 0) - (b.line ?? 0) || cmp(a.evidence, b.evidence));
	for (const u of sorted) {
		const key = `${u.file}\0${u.evidence}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(u);
	}
	return out.slice(0, max);
}
function sha256(data) {
	return createHash("sha256").update(data).digest("hex");
}
function withoutUndefined(e) {
	const out = {
		file: e.file,
		line: e.line
	};
	if (e.snippet !== void 0) out.snippet = e.snippet;
	if (e.detail !== void 0) out.detail = e.detail;
	return out;
}
/**
* Parses and visits one file. A pathologically nested file can exhaust the stack in the
* parser or the walker; that is reported as an unparseable file rather than thrown.
*/
function analyzeText(text) {
	try {
		const parsed = parseJs(text);
		return "error" in parsed ? parsed : { facts: analyzeProgram(parsed.program) };
	} catch (err) {
		if (err instanceof RangeError) return { error: "too deeply nested to analyze" };
		throw err;
	}
}
var PKG_DOC_FIELDS, cmp;
var init_analyze = __esmMin((() => {
	init_src$1();
	init_classify();
	init_parse();
	init_scripts();
	init_signals();
	init_text();
	init_types();
	init_visit();
	PKG_DOC_FIELDS = /* @__PURE__ */ new Set([
		"repository",
		"homepage",
		"bugs",
		"author",
		"contributors",
		"maintainers",
		"funding",
		"license"
	]);
	cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
}));
// ../packages/analyzer/src/index.ts
var src_exports = /* @__PURE__ */ __exportAll({
	ANALYSIS_REVISION: () => 1,
	CAPABILITIES: () => CAPABILITIES,
	SIGNAL_SEVERITY: () => SIGNAL_SEVERITY,
	VERSION: () => VERSION$1,
	analyzePackage: () => analyzePackage,
	binaryFormat: () => binaryFormat,
	classifyFile: () => classifyFile,
	compareSignals: () => compareSignals,
	isSensitiveEnvKey: () => isSensitiveEnvKey,
	looksBundled: () => looksBundled,
	looksMinified: () => looksMinified,
	profileFindings: () => profileFindings
}), VERSION$1;
var init_src = __esmMin((() => {
	init_analyze();
	init_classify();
	init_signals();
	init_text();
	init_types();
	VERSION$1 = "0.0.0";
}));
// ../packages/diff/src/deltas.ts
init_src();
init_src$1();
/** Scripts compared by {@link scriptDelta}, in this order. */
const SCRIPT_NAMES = [
	"preinstall",
	"install",
	"postinstall",
	"prepare"
];
const byCodeUnit = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function minus(a, b) {
	const drop = new Set(b);
	return [...new Set([...a].filter((x) => !drop.has(x)))].toSorted(byCodeUnit);
}
const used = (p) => new Set(CAPABILITIES.filter((c) => p.capabilities[c].length > 0));
/** Capabilities used in B and not in A, and the reverse, in {@link CAPABILITIES} order. */
function capabilityDelta(a, b) {
	const inA = used(a);
	const inB = used(b);
	return {
		added: CAPABILITIES.filter((c) => inB.has(c) && !inA.has(c)),
		removed: CAPABILITIES.filter((c) => inA.has(c) && !inB.has(c))
	};
}
/** Signals compared by id: every signal of one side whose id the other side lacks. */
function signalDelta(a, b) {
	return {
		added: signalsNotIn(b, signalIds(a)),
		removed: signalsNotIn(a, signalIds(b))
	};
}
const signalIds = (p) => new Set(p.signals.map((s) => s.id));
const signalsNotIn = (p, ids) => p.signals.filter((s) => !ids.has(s.id));
/** Install scripts whose command differs (including appearing or disappearing). */
function scriptDelta(a, b) {
	const out = {};
	for (const name of SCRIPT_NAMES) {
		const from = a.scripts[name];
		const to = b.scripts[name];
		if (from === to) continue;
		out[name] = {
			...from === void 0 ? {} : { from },
			...to === void 0 ? {} : { to }
		};
	}
	return out;
}
/**
* Declared dependencies (`dependencies`, then `optionalDependencies`, then
* `peerDependencies`; the first one wins for a name). Only string ranges count.
*/
function declaredDependencies(meta) {
	const out = /* @__PURE__ */ new Map();
	for (const group of [
		meta.dependencies,
		meta.optionalDependencies,
		meta.peerDependencies
	]) {
		if (typeof group !== "object" || group === null) continue;
		for (const [name, range] of Object.entries(group)) if (typeof range === "string" && !out.has(name)) out.set(name, range);
	}
	return out;
}
/** Dependency names added, removed, or with a changed range. */
function dependencyDelta(metaA, metaB) {
	const a = declaredDependencies(metaA);
	const b = declaredDependencies(metaB);
	return {
		added: minus(b.keys(), a.keys()),
		removed: minus(a.keys(), b.keys()),
		changed: [...b.keys()].filter((n) => a.has(n) && a.get(n) !== b.get(n)).toSorted(byCodeUnit)
	};
}
/** True when a file's size moved by more than {@link LARGE_CHANGE_RATIO} or {@link LARGE_CHANGE_BYTES}. */
function isLargeChange(sizeA, sizeB) {
	const moved = Math.abs(sizeB - sizeA);
	return moved > 102400 || moved > sizeA * .5;
}
/** Files added, removed, or changed a lot (same path, different hash, large size change). */
function fileDelta(a, b) {
	const filesA = new Map(a.files.map((f) => [f.path, f]));
	const pathsB = b.files.map((f) => f.path);
	const changedLarge = b.files.filter((f) => {
		const old = filesA.get(f.path);
		return old !== void 0 && old.sha256 !== f.sha256 && isLargeChange(old.size, f.size);
	}).map((f) => f.path);
	return {
		added: minus(pathsB, filesA.keys()),
		removed: minus(filesA.keys(), pathsB),
		changedLarge: changedLarge.toSorted(byCodeUnit)
	};
}
/** Endpoints in B and not in A. */
function endpointDelta(a, b) {
	return { added: minus(b.endpoints, a.endpoints) };
}
/** Literal env keys read in B and not in A. */
function envKeyDelta(a, b) {
	return { added: minus(b.envKeys, a.envKeys) };
}
/** `_npmUser.name`, when it is a non-empty string. */
function publisherName(meta) {
	const name = meta._npmUser?.name;
	return typeof name === "string" && name !== "" ? name : null;
}
/** Set when both versions name a publisher and the names differ. */
function publisherDelta(metaA, metaB) {
	const from = publisherName(metaA);
	const to = publisherName(metaB);
	return from !== null && to !== null && from !== to ? {
		from,
		to
	} : void 0;
}
/** `dropped` or `added` when attestations disappear or appear between A and B. */
function provenanceDelta(metaA, metaB) {
	const a = hasAttestations(metaA);
	return a === hasAttestations(metaB) ? void 0 : a ? "dropped" : "added";
}
// ../packages/diff/src/rules.ts
init_src();
init_src$1();
/** New capabilities that are `high` instead of `medium`. */
const HIGH_RISK_CAPABILITIES = /* @__PURE__ */ new Set([
	"child_process",
	"dynamic_code",
	"native_addon"
]);
/** Scripts npm runs on install (`prepare` is not run for registry installs). */
const INSTALL_SCRIPTS = SCRIPT_NAMES.filter((s) => s !== "prepare");
const ENUMERATION = /^enumerates process\.env\b/;
function cap(evidence) {
	if (evidence.length <= 10) return evidence;
	return [...evidence.slice(0, 10), { detail: `and ${evidence.length - 10} more` }];
}
/** Host part of a normalized endpoint (`scheme://host[:port]/path`, host, or IP). */
function endpointHost(endpoint) {
	const rest = endpoint.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
	const bracketed = /^\[([^\]]*)\]/.exec(rest);
	if (bracketed) return bracketed[1] ?? "";
	if (isIP(rest) === 6) return rest;
	return rest.split(/[/:?#]/, 1)[0] ?? "";
}
/** True when the endpoint's host is an IP literal. */
function isRawIpEndpoint(endpoint) {
	return isIP(endpointHost(endpoint)) !== 0;
}
const CORE = /^v?(\d+)\.(\d+)\.(\d+)/;
/** True when `to` has the same major and minor as `from` and a higher patch. Prerelease tags are ignored. */
function isPatchBump(from, to) {
	const a = CORE.exec(from);
	const b = CORE.exec(to);
	if (!a || !b) return false;
	return a[1] === b[1] && a[2] === b[2] && Number(b[3]) > Number(a[3]);
}
function enumerations(p) {
	return p.signals.filter((s) => s.id === "env-sensitive-read").flatMap((s) => s.evidence).filter((e) => e.detail !== void 0 && ENUMERATION.test(e.detail));
}
/** Builds every finding for one package diff, sorted. */
function diffFindings(input) {
	const { delta, a, b, metaA, metaB, ctx } = input;
	const out = [];
	const pkg = delta.name;
	const from = escapeUnsafe(delta.from, 64);
	const add = (id, severity, message, evidence) => {
		out.push({
			id,
			severity,
			package: pkg,
			version: delta.to,
			message,
			evidence: cap(evidence),
			docsUrl: findingDocsUrl(id)
		});
	};
	const scripts = INSTALL_SCRIPTS.filter((s) => delta.scriptDelta[s]?.to !== void 0);
	if (scripts.length > 0) add("diff-new-install-script", "high", `adds or changes install scripts since ${from}: ${scripts.join(", ")}`, scripts.map((s) => {
		const change = delta.scriptDelta[s] ?? {};
		return {
			file: "package.json",
			snippet: `${s}: ${escapeUnsafe(change.to ?? "")}`,
			detail: change.from === void 0 ? "new script" : `was: ${escapeUnsafe(change.from)}`
		};
	}));
	for (const c of delta.capabilityDelta.added) {
		const evidence = b.capabilities[c].map((u) => ({
			file: u.file,
			...u.line === void 0 ? {} : { line: u.line },
			snippet: u.evidence
		}));
		if (c === "net") add("diff-new-network-in-non-network-pkg", "high", `uses the network; ${from} did not`, evidence);
		else add("diff-new-capability", HIGH_RISK_CAPABILITIES.has(c) ? "high" : "medium", `new capability: ${c} (not used in ${from})`, evidence);
	}
	const sensitiveKeys = delta.envKeyDelta.added.filter(isSensitiveEnvKey);
	const newEnumeration = enumerations(a).length === 0 ? enumerations(b) : [];
	if (sensitiveKeys.length > 0 || newEnumeration.length > 0) {
		const what = [...sensitiveKeys.length > 0 ? [`sensitive environment variables (${sensitiveKeys.map((k) => escapeUnsafe(k, 64)).join(", ")})`] : [], ...newEnumeration.length > 0 ? ["the whole environment"] : []];
		const keyEvidence = sensitiveKeys.map((k) => ({
			snippet: `process.env.${escapeUnsafe(k, 100)}`,
			detail: "new sensitive key"
		}));
		add("diff-new-sensitive-env", "high", `newly reads ${what.join(" and ")}`, [...newEnumeration, ...keyEvidence]);
	}
	if (delta.endpointDelta.added.length > 0) {
		const ips = delta.endpointDelta.added.filter(isRawIpEndpoint);
		const evidence = delta.endpointDelta.added.map((e) => ({
			snippet: escapeUnsafe(e),
			...ips.includes(e) ? { detail: "raw IP" } : {}
		}));
		const n = delta.endpointDelta.added.length;
		add("diff-new-endpoint", ips.length > 0 ? "high" : "medium", `${n} new hardcoded endpoint${n === 1 ? "" : "s"}${ips.length > 0 ? `, ${ips.length} raw IP` : ""}`, evidence.toSorted((x, y) => Number("detail" in y) - Number("detail" in x)));
	}
	const hidden = delta.signalDelta.added.filter((s) => s.id === "obfuscation" || s.id === "encoded-payload");
	if (hidden.length > 0) add("diff-new-obfuscation", "critical", `new ${[...new Set(hidden.map((s) => s.id))].join(" and ")} not present in ${from}`, hidden.flatMap((s) => s.evidence));
	for (const dep of delta.dependencyDelta.added) {
		const young = ctx.isYoungDependency?.(dep) === true;
		add("diff-new-dependency", young ? "high" : "low", `new dependency: ${escapeUnsafe(dep, 214)}${young ? " (itself published recently)" : ""}`, [{
			file: "package.json",
			snippet: escapeUnsafe(dep, 214),
			...young ? { detail: "package-too-new" } : {}
		}]);
	}
	const publisher = publisherFinding(metaA, metaB, ctx);
	if (publisher !== null) add("diff-publisher-changed", "high", `published by ${escapeUnsafe(publisher.to, 100)}, not by a recent publisher (${publisher.previous.map((p) => escapeUnsafe(p, 100)).join(", ")})`, [{ detail: `${from} was published by ${escapeUnsafe(publisherName(metaA) ?? "unknown", 100)}` }]);
	if (delta.provenanceDelta === "dropped") add("diff-provenance-dropped", "high", `has no provenance attestation; ${from} had one`, []);
	if (isPatchBump(delta.from, delta.to) && (delta.capabilityDelta.added.length > 0 || scripts.length > 0)) add("diff-semver-mismatch", "medium", `patch release adds ${[...delta.capabilityDelta.added.map((c) => `capability ${c}`), ...scripts.map((s) => `${s} script`)].join(", ")}`, [{ detail: `${from} → ${escapeUnsafe(delta.to, 64)}` }]);
	return out.toSorted(compareFindings);
}
function publisherFinding(metaA, metaB, ctx) {
	if (ctx.packument !== void 0) {
		const change = publisherChange(ctx.packument, metaB, ctx.now === void 0 ? {} : { now: ctx.now });
		return change === null ? null : {
			to: change.publisher,
			previous: change.previous
		};
	}
	const was = publisherName(metaA);
	const now = publisherName(metaB);
	if (was === null || now === null || was === now || isTrustedPublish(metaB)) return null;
	return {
		to: now,
		previous: [was]
	};
}
/** The highest severity, escalated to `critical` when two or more findings are `high`. `info` when empty. */
function diffRisk(findings) {
	if (findings.filter((f) => f.severity === "high").length >= 2) return "critical";
	return findings.map((f) => f.severity).toSorted(compareSeverity)[0] ?? "info";
}
// ../packages/diff/src/diff.ts
init_src$1();
/**
* Compares what version A of a package could do with what version B can do, and reports
* the changes that matter for supply-chain risk. Pure: it never touches the network.
* Spec: `docs/specs/diff.md`.
*
* @param a - Analyzer profile of the old version.
* @param b - Analyzer profile of the new version.
* @param metaA - Registry metadata of the old version (dependencies, publisher, provenance).
* @param metaB - Registry metadata of the new version.
* @param ctx - Optional registry context; with a packument the publisher check uses the
*   package's publish history.
* @throws DepwardError `INVALID_ARGUMENT` when the profiles and metadata are not all for
*   the same package, or a profile's version doesn't match its metadata.
*
* @example
* ```ts
* const diff = diffPackages(profileA, profileB, metaA, metaB);
* if (diff.risk === "critical") console.log(diff.findings.map((f) => f.message));
* ```
*/
function diffPackages(a, b, metaA, metaB, ctx = {}) {
	if (a.name !== b.name || metaA.name !== a.name || metaB.name !== a.name) throw new DepwardError("INVALID_ARGUMENT", "diffPackages needs two versions of the same package");
	if (metaA.version !== a.version || metaB.version !== b.version) throw new DepwardError("INVALID_ARGUMENT", "diffPackages: profile and metadata versions differ");
	const publisher = publisherDelta(metaA, metaB);
	const provenance = provenanceDelta(metaA, metaB);
	const delta = {
		name: a.name,
		from: a.version,
		to: b.version,
		capabilityDelta: capabilityDelta(a, b),
		signalDelta: signalDelta(a, b),
		scriptDelta: scriptDelta(a, b),
		dependencyDelta: dependencyDelta(metaA, metaB),
		fileDelta: fileDelta(a, b),
		endpointDelta: endpointDelta(a, b),
		envKeyDelta: envKeyDelta(a, b),
		...publisher === void 0 ? {} : { publisherDelta: publisher },
		...provenance === void 0 ? {} : { provenanceDelta: provenance }
	};
	const findings = diffFindings({
		delta,
		a,
		b,
		metaA,
		metaB,
		ctx
	});
	return {
		...delta,
		findings,
		risk: diffRisk(findings)
	};
}
// ../packages/gate/src/command/managers.ts
const COMMON_VALUES = [
	"--registry",
	"--loglevel",
	"--cpu",
	"--os",
	"--libc",
	"--network-concurrency"
];
[.../* @__PURE__ */ new Set([
	...COMMON_VALUES,
	"--prefix",
	"-C",
	"--tag",
	"--workspace",
	"-w",
	"--cache",
	"--userconfig",
	"--globalconfig",
	"--omit",
	"--include",
	"--install-strategy",
	"--save-prefix",
	"--before",
	"--otp",
	"--scope",
	"--location",
	"--auth-type",
	"--fetch-timeout",
	"--fetch-retries",
	"--script-shell",
	"--node-options",
	"--lockfile-version",
	"--access",
	"--depth"
])];
[...COMMON_VALUES];
[...COMMON_VALUES];
[...COMMON_VALUES];
const NPM_INSTALL = /* @__PURE__ */ new Set([
	"install",
	"i",
	"in",
	"ins",
	"inst",
	"insta",
	"instal",
	"isnt",
	"isnta",
	"isntal",
	"isntall",
	"add",
	"install-test",
	"it"
]);
const NPM_LOCKFILE = /* @__PURE__ */ new Set([
	"ci",
	"clean-install",
	"ic",
	"install-clean",
	"isntall-clean",
	"install-ci-test",
	"cit"
]);
[...NPM_INSTALL, ...NPM_LOCKFILE];
// ../packages/gate/src/command/shell.ts
init_src$1();
// ../packages/gate/src/command/spec.ts
init_src$1();
// ../packages/gate/src/command/analyze.ts
init_src$1();
// ../packages/gate/src/registry/edit-distance.ts
/**
* OSA edit distance between `a` and `b`: insertions, deletions, substitutions, and
* swaps of two adjacent characters each cost 1 (a substring is edited at most once).
* Compared by UTF-16 code unit. Returns `max + 1` as soon as the distance is known to
* exceed `max`, so a scan over thousands of names stays cheap.
*/
function editDistance(a, b, max = Number.POSITIVE_INFINITY) {
	if (a === b) return 0;
	if (Math.abs(a.length - b.length) > max) return max + 1;
	if (a.length === 0) return Math.min(b.length, max + 1);
	if (b.length === 0) return Math.min(a.length, max + 1);
	let before = new Uint32Array(b.length + 1);
	let prev = new Uint32Array(b.length + 1);
	let curr = new Uint32Array(b.length + 1);
	for (let j = 0; j <= b.length; j++) prev[j] = j;
	let prevMin = 0;
	for (let i = 1; i <= a.length; i++) {
		curr[0] = i;
		let rowMin = i;
		const ca = a.charCodeAt(i - 1);
		for (let j = 1; j <= b.length; j++) {
			const cb = b.charCodeAt(j - 1);
			const cost = ca === cb ? 0 : 1;
			let v = Math.min((prev[j] ?? 0) + 1, (curr[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
			if (i > 1 && j > 1 && ca === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === cb) v = Math.min(v, (before[j - 2] ?? 0) + 1);
			curr[j] = v;
			if (v < rowMin) rowMin = v;
		}
		if (rowMin > max && prevMin > max) return max + 1;
		prevMin = rowMin;
		[before, prev, curr] = [
			prev,
			curr,
			before
		];
	}
	const d = prev[b.length] ?? 0;
	return d > max ? max + 1 : d;
}
/** Folds case, scope markers, and separators: `@Foo/bar_baz.js` → `foobarbazjs`. */
function separatorKey(name) {
	return name.toLowerCase().replace(/[@/._-]/g, "");
}
function scopeOf(name) {
	return name.startsWith("@") && name.includes("/") ? name.slice(0, name.indexOf("/")).toLowerCase() : null;
}
/** Maximum edit distance at which `target` (a popular name) counts as similar. */
function maxDistanceFor(target) {
	return target.length <= 5 ? 1 : 2;
}
/** Builds a {@link PopularIndex}. Later duplicates of a name are ignored. */
function createPopularIndex(packages) {
	const byName = /* @__PURE__ */ new Map();
	const byLength = /* @__PURE__ */ new Map();
	const byKey = /* @__PURE__ */ new Map();
	for (const p of packages) {
		const name = p.name.toLowerCase();
		if (byName.has(name)) continue;
		const entry = {
			name,
			weeklyDownloads: p.weeklyDownloads
		};
		byName.set(name, entry);
		push(byLength, name.length, entry);
		push(byKey, separatorKey(name), entry);
	}
	return {
		size: byName.size,
		downloads: (name) => byName.get(name.toLowerCase())?.weeklyDownloads,
		similar(input) {
			const name = input.toLowerCase();
			const scope = scopeOf(name);
			const found = /* @__PURE__ */ new Map();
			const consider = (p, kind, distance) => {
				if (p.name === name || scope !== null && scopeOf(p.name) === scope) return;
				const prev = found.get(p.name);
				if (prev === void 0 || distance < prev.distance) found.set(p.name, {
					...p,
					kind,
					distance
				});
			};
			for (const p of byKey.get(separatorKey(name)) ?? []) consider(p, scope === null && scopeOf(p.name) === null ? "separator" : "scope", editDistance(name, p.name));
			for (let len = name.length - 2; len <= name.length + 2; len++) for (const p of byLength.get(len) ?? []) {
				const max = maxDistanceFor(p.name);
				const d = editDistance(name, p.name, max);
				if (d <= max) consider(p, "edit-distance", d);
			}
			return [...found.values()].toSorted((a, b) => a.distance - b.distance || b.weeklyDownloads - a.weeklyDownloads || (a.name < b.name ? -1 : 1));
		}
	};
}
function push(map, key, value) {
	const list = map.get(key);
	if (list) list.push(value);
	else map.set(key, [value]);
}
// ../packages/gate/src/registry/data.ts
init_src$1();
/** Builds {@link GateData} from in-memory lists, for tests and custom data sets. */
function createGateData(popular, hallucinated) {
	return {
		popular: createPopularIndex(popular),
		hallucinated: new Map(hallucinated.filter((h) => h.ecosystem === "npm").map((h) => [h.name.toLowerCase(), h]))
	};
}
function isRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function invalid(file, why) {
	return new DepwardError("INTERNAL", `data file ${file} is invalid: ${why}`);
}
/** Validates the contents of `popular-packages.json`. */
function parsePopular(doc) {
	if (!isRecord(doc) || doc["schemaVersion"] !== 1 || !Array.isArray(doc["packages"])) throw invalid("popular-packages.json", "expected schemaVersion 1 with a packages array");
	return doc["packages"].map((p) => {
		if (!isRecord(p) || typeof p["name"] !== "string" || typeof p["weeklyDownloads"] !== "number") throw invalid("popular-packages.json", "bad package entry");
		assertPackageName(p["name"]);
		return {
			name: p["name"],
			weeklyDownloads: p["weeklyDownloads"]
		};
	});
}
/** Validates the contents of `hallucinated-names.json`. */
function parseHallucinated(doc) {
	if (!isRecord(doc) || doc["schemaVersion"] !== 1 || !Array.isArray(doc["entries"])) throw invalid("hallucinated-names.json", "expected schemaVersion 1 with an entries array");
	return doc["entries"].map((e) => {
		const fields = [
			"name",
			"ecosystem",
			"firstSeen",
			"source",
			"suggestion"
		];
		if (!isRecord(e) || !fields.every((f) => typeof e[f] === "string")) throw invalid("hallucinated-names.json", "bad entry");
		const [name, ecosystem, firstSeen, source, suggestion] = fields.map((f) => e[f]);
		assertPackageName(name);
		assertPackageName(suggestion);
		return {
			name,
			ecosystem,
			firstSeen,
			source,
			suggestion
		};
	});
}
/**
* Directory holding the data files. A built package reads `dist/data/`. When running
* from TypeScript sources inside this repository, it reads the repository's `data/`.
* The source-mode path is only used for `.ts` modules, so an installed package never
* looks outside its own directory.
*/
function dataDir() {
	return import.meta.url.endsWith(".ts") ? new URL("../../../../data/", import.meta.url) : new URL("./data/", import.meta.url);
}
async function readJson(file) {
	try {
		return JSON.parse(await readFile(new URL(file, dataDir()), "utf8"));
	} catch (cause) {
		throw new DepwardError("INTERNAL", `could not read data file ${file}`, { cause });
	}
}
let loaded;
/** Loads the bundled data files once per process. */
function loadGateData() {
	if (loaded === void 0) {
		const p = (async () => {
			const [popular, hallucinated] = await Promise.all([readJson("popular-packages.json"), readJson("hallucinated-names.json")]);
			return createGateData(parsePopular(popular), parseHallucinated(hallucinated));
		})();
		loaded = p;
		p.catch(() => {
			if (loaded === p) loaded = void 0;
		});
	}
	return loaded;
}
// ../packages/gate/src/registry/checks.ts
init_src$1();
const DAY = 864e5;
function finding(id, severity, pkg, version, message, details = []) {
	return {
		id,
		severity,
		package: pkg,
		...version === null ? {} : { version },
		message,
		evidence: details.map((detail) => ({ detail })),
		docsUrl: findingDocsUrl(id)
	};
}
function toError$1(err) {
	return isDepwardError(err) ? err : new DepwardError("INTERNAL", "registry check failed", { cause: err });
}
const plural$1 = (n, unit) => `${n} ${unit}${n === 1 ? "" : "s"}`;
const days = (ms) => {
	const d = ms / DAY;
	return d < 1 ? plural$1(Math.max(0, Math.round(d * 24)), "hour") : plural$1(Math.floor(d), "day");
};
/** First publish of the package: `time.created`, else its earliest version. */
function createdAt(packument) {
	const created = Date.parse(packument.time["created"] ?? "");
	if (Number.isFinite(created)) return created;
	let first = null;
	for (const v of Object.keys(packument.versions)) {
		const at = publishTime(packument, v);
		if (at !== null && (first === null || at < first)) first = at;
	}
	return first;
}
/**
* Runs every registry check for one package. It never throws for registry or network
* failures: those land in `errors`, alongside any findings already made.
*/
async function checkRegistry(input, opts) {
	const now = (opts.now ?? Date.now)();
	const minVersionAge = (opts.minVersionAgeDays ?? 7) * DAY;
	const minPackageAge = (opts.minPackageAgeDays ?? 30) * DAY;
	const minDownloads = opts.minWeeklyDownloads ?? 500;
	const ratio = opts.typosquatRatio ?? 100;
	const { name, range } = input;
	const findings = [];
	const errors = [];
	const suggestion = {};
	let version = null;
	let meta = null;
	let weeklyDownloads = null;
	const done = () => ({
		name,
		range,
		version,
		meta,
		findings: sortFindings(findings),
		suggestion,
		weeklyDownloads,
		errors
	});
	let data = opts.data ?? null;
	if (data === null) try {
		data = await loadGateData();
	} catch (err) {
		errors.push(toError$1(err));
	}
	const known = data?.hallucinated.get(name.toLowerCase());
	if (known) {
		suggestion.name = known.suggestion;
		findings.push(finding("known-hallucinated-name", "critical", name, null, `${name} is a package name AI models are documented to hallucinate. Did you mean ${known.suggestion}?`, [`first seen ${known.firstSeen}: ${known.source}`]));
	}
	const downloadsP = opts.registry.weeklyDownloads(name).then((n) => ({
		ok: true,
		n
	}), (err) => ({
		ok: false,
		err
	}));
	let packument;
	try {
		packument = await opts.registry.packument(name);
	} catch (err) {
		errors.push(toError$1(err));
		return done();
	}
	if (packument === null) {
		const similar = data?.popular.similar(name)[0];
		if (suggestion.name === void 0 && similar) suggestion.name = similar.name;
		const hint = suggestion.name === void 0 ? "" : ` Did you mean ${suggestion.name}?`;
		findings.push(finding("package-not-found", "high", name, null, `${name} does not exist on the registry. It may be a typo or a name an AI model made up.${hint}`));
		return done();
	}
	const created = createdAt(packument);
	if (created !== null && now - created < minPackageAge) findings.push(finding("package-too-new", "medium", name, null, `${name} was first published ${days(now - created)} ago (minimum ${opts.minPackageAgeDays ?? 30} days).`, [`created ${new Date(created).toISOString()}`]));
	const dl = await downloadsP;
	if (dl.ok) weeklyDownloads = dl.n;
	else errors.push(toError$1(dl.err));
	if (weeklyDownloads !== null && weeklyDownloads < minDownloads) findings.push(finding("low-downloads", "medium", name, null, `${name} has ${weeklyDownloads} downloads in the last week (minimum ${minDownloads}).`));
	if (data && data.popular.downloads(name) === void 0) {
		const floor = ratio * Math.max(weeklyDownloads ?? 0, 1);
		const targets = data.popular.similar(name).filter((p) => p.weeklyDownloads >= floor).slice(0, 3);
		const top = targets[0];
		if (top) {
			suggestion.name ??= top.name;
			const how = top.kind === "edit-distance" ? `${top.distance} character${top.distance === 1 ? "" : "s"} away from` : `a ${top.kind} swap of`;
			findings.push(finding("typosquat-suspect", "high", name, null, `${name} is ${how} the popular package ${top.name}, which has far more downloads. Did you mean ${top.name}?`, targets.map((t) => `${t.name}: ${t.weeklyDownloads} weekly downloads (${t.kind}, distance ${t.distance})`)));
		}
	}
	const added = addedMaintainers(packument, now, opts.maintainerWindowDays ?? 30);
	if (added.length > 0) findings.push(finding("maintainer-added-recently", "low", name, null, `${name} gained ${added.length === 1 ? "a maintainer" : `${added.length} maintainers`} in the last ${opts.maintainerWindowDays ?? 30} days.`, added.slice(0, 10).map((a) => `${escapeUnsafe(a.name, 80)} first listed on ${a.version}`)));
	meta = resolveVersion(packument, range);
	if (meta === null) {
		const tags = Object.entries(packument["dist-tags"]).slice(0, 10).map(([t, v]) => `${escapeUnsafe(t, 40)}: ${escapeUnsafe(v, 40)}`);
		findings.push(finding("version-not-found", "high", name, null, `No version of ${name} matches ${JSON.stringify(escapeUnsafe(range, 80))}.`, tags.length ? [`dist-tags: ${tags.join(", ")}`] : []));
		return done();
	}
	version = meta.version;
	const published = publishTime(packument, version);
	if (published !== null && now - published < minVersionAge) {
		const cutoff = now - minVersionAge;
		const inRange = resolveVersion(packument, range, { publishedBefore: cutoff });
		const older = inRange ?? resolveVersion(packument, "*", { publishedBefore: cutoff });
		if (older) suggestion.version = older.version;
		const isTag = Object.hasOwn(packument["dist-tags"], range.trim() === "" ? "latest" : range.trim());
		const label = inRange || isTag ? "" : " (outside the requested range)";
		const hint = older ? ` Use ${name}@${older.version}${label} instead.` : "";
		findings.push(finding("version-too-new", "medium", name, version, `${name}@${version} was published ${days(now - published)} ago (minimum ${opts.minVersionAgeDays ?? 7} days).${hint}`, [`published ${new Date(published).toISOString()}`]));
	}
	const pub = publisherChange(packument, meta, { now });
	if (pub) findings.push(finding("publisher-changed", "medium", name, version, `${name}@${version} was published by ${escapeUnsafe(pub.publisher, 80)}, who published none of the previous versions.`, [`previous publishers: ${pub.previous.map((p) => escapeUnsafe(p, 80)).join(", ")}`]));
	const attested = provenanceDrop(packument, meta);
	if (attested) findings.push(finding("provenance-dropped", "high", name, version, `${name}@${version} has no provenance attestation, but ${attested.version} did. It may not have been built by the usual CI.`));
	if (isDeprecated(meta)) findings.push(finding("deprecated", "low", name, version, `${name}@${version} is deprecated.`, [escapeUnsafe(meta.deprecated ?? "", 200)]));
	return done();
}
// ../packages/gate/src/tarball/cache.ts
init_src$1();
/** Cache namespace of analysis results. */
const ANALYSIS_NAMESPACE = "analysis";
/**
* The cache key for one version's analysis, or `null` when the version has no
* sha256/384/512 integrity hash (such results are never cached).
*/
function analysisCacheKey(meta, opts, analyzer) {
	const hash = meta.dist.integrity === void 0 ? null : strongestHash(meta.dist.integrity);
	if (hash === null) return null;
	const limits = JSON.stringify({
		tar: opts.tarLimits ?? {},
		analyze: opts.analyze ?? {}
	});
	return `analyzer@${analyzer.VERSION}:r${analyzer.ANALYSIS_REVISION}:${hash.algorithm}-${hash.digest}:${limits}`;
}
const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
/** A shallow shape check: enough that `profileFindings` can't trip over a stale or foreign entry. */
function isProfile(v) {
	return isObject(v) && typeof v["name"] === "string" && typeof v["version"] === "string" && isObject(v["scripts"]) && isObject(v["capabilities"]) && Array.isArray(v["signals"]) && Array.isArray(v["files"]) && Array.isArray(v["endpoints"]) && Array.isArray(v["envKeys"]) && isObject(v["stats"]);
}
/** Reads a cached profile, or `null` on a miss or anything unreadable. */
async function readCachedProfile(cache, key) {
	try {
		const entry = await cache.get(ANALYSIS_NAMESPACE, key);
		if (entry === null) return null;
		const value = JSON.parse(new TextDecoder().decode(entry.body));
		return isProfile(value) ? value : null;
	} catch {
		return null;
	}
}
/** Stores a profile. A failed write is ignored: the next check just analyzes again. */
async function writeCachedProfile(cache, key, profile, now) {
	try {
		await cache.set(ANALYSIS_NAMESPACE, key, {
			body: new TextEncoder().encode(JSON.stringify(profile)),
			storedAt: now
		});
	} catch {}
}
// ../packages/gate/src/tarball/check.ts
init_src$1();
/**
* Loads `@depward/analyzer` (and acorn). The tarball stage does this on first use, so
* hook calls that never reach it don't pay for it. Long-running processes can call this
* at startup to keep their first check fast.
*/
function preloadAnalyzer() {
	return Promise.resolve().then(() => (init_src(), src_exports));
}
const UNSAFE_CODES = /* @__PURE__ */ new Set([
	"UNSAFE_PATH",
	"INVALID_ARCHIVE",
	"LIMIT_EXCEEDED"
]);
function failure(meta, err) {
	if (!isDepwardError(err)) return { error: new DepwardError("INTERNAL", "tarball check failed", { cause: err }) };
	const base = {
		package: meta.name,
		version: meta.version,
		evidence: [{ detail: err.message }]
	};
	if (err.code === "INTEGRITY_MISMATCH") return { finding: {
		id: "tarball-integrity-mismatch",
		severity: "critical",
		...base,
		message: `The tarball of ${meta.name}@${meta.version} does not match the integrity hash the registry published for it. It may have been tampered with.`,
		docsUrl: findingDocsUrl("tarball-integrity-mismatch")
	} };
	if (UNSAFE_CODES.has(err.code)) return { finding: {
		id: "tarball-unsafe",
		severity: "high",
		...base,
		message: `The tarball of ${meta.name}@${meta.version} can't be analyzed safely: it is malformed, contains unsafe paths, or exceeds a size limit.`,
		docsUrl: findingDocsUrl("tarball-unsafe")
	} };
	return { error: err };
}
/**
* Downloads and statically analyzes one version. It never throws for registry,
* network, or archive failures: archive problems become `tarball-*` findings, and
* transient failures land in `errors`.
*/
async function checkTarball(meta, opts) {
	const { name, version } = meta;
	const done = (findings, profile, errors) => ({
		name,
		version,
		findings: sortFindings(findings),
		profile,
		errors
	});
	const analyzer = await preloadAnalyzer();
	const cache = opts.analysisCache ?? null;
	const key = cache === null ? null : analysisCacheKey(meta, opts, analyzer);
	let profile = cache !== null && key !== null ? await readCachedProfile(cache, key) : null;
	if (profile !== null) try {
		return done(reported(analyzer.profileFindings(profile), name, version), profile, []);
	} catch {
		profile = null;
	}
	try {
		const bytes = await opts.registry.tarball(meta);
		profile = analyzer.analyzePackage(readTarball(bytes, opts.tarLimits), opts.analyze);
	} catch (err) {
		const { finding, error } = failure(meta, err);
		return done(finding ? [finding] : [], null, error ? [error] : []);
	}
	const findings = reported(analyzer.profileFindings(profile), name, version);
	if (cache !== null && key !== null) await writeCachedProfile(cache, key, profile, Date.now());
	return done(findings, profile, []);
}
function reported(findings, name, version) {
	return findings.map((f) => ({
		...f,
		package: name,
		version
	}));
}
// ../packages/gate/src/check.ts
init_src$1();
/**
* Runs the registry checks, then (when a version resolved) the tarball checks. Never
* throws for registry, network, or archive failures; see `errors` and the `tarball-*`
* findings.
*/
async function checkPackage(input, opts) {
	const registry = await checkRegistry(input, opts);
	if (registry.meta === null || opts.tarball === false || opts.analyzeTarball?.(registry) === false) return {
		...registry,
		profile: null
	};
	const tarball = await checkTarball(registry.meta, opts);
	return {
		...registry,
		findings: sortFindings([...registry.findings, ...tarball.findings]),
		errors: [...registry.errors, ...tarball.errors],
		profile: tarball.profile
	};
}
// ../packages/gate/src/policy/actions.ts
const RANK = {
	allow: 0,
	ask: 1,
	deny: 2
};
/** The more severe of two actions (`deny` > `ask` > `allow`). */
function stricter(a, b) {
	return RANK[b] > RANK[a] ? b : a;
}
/** The most severe action in `actions`, or `allow` when there are none. */
function strictest(actions) {
	let result = "allow";
	for (const a of actions) result = stricter(result, a);
	return result;
}
/**
* Default actions for every finding ID depward emits. Registry, command, and archive
* findings follow the gate spec's tables. Analyzer signals follow their severity
* (critical → deny, high → ask, lower → allow), except `env-sensitive-read`: reading a
* token-like variable alone is common in benign code, and the token-stealer shape
* (read flowing into a network call) is `env-exfil-pattern`, which denies.
*/
const DEFAULT_ACTIONS = {
	"non-registry-source": "ask",
	"unparseable-command": "ask",
	"global-install": "allow",
	"package-not-found": "deny",
	"known-hallucinated-name": "deny",
	"version-not-found": "deny",
	"version-too-new": "ask",
	"package-too-new": "ask",
	"low-downloads": "ask",
	"typosquat-suspect": "ask",
	"publisher-changed": "ask",
	"maintainer-added-recently": "allow",
	"provenance-dropped": "ask",
	deprecated: "allow",
	"tarball-integrity-mismatch": "deny",
	"tarball-unsafe": "deny",
	"lockfile-integrity-mismatch": "deny",
	"install-script": "allow",
	"install-script-network": "ask",
	"env-sensitive-read": "allow",
	"env-exfil-pattern": "deny",
	"fs-sensitive-path": "ask",
	obfuscation: "ask",
	"encoded-payload": "ask",
	"high-entropy-string": "allow",
	"hardcoded-endpoint": "allow",
	"raw-ip-endpoint": "allow",
	"native-binary": "allow",
	"unparseable-file": "allow",
	"oversized-file": "allow",
	"minified-only": "allow",
	denylisted: "deny"
};
const BY_SEVERITY = {
	critical: "deny",
	high: "ask",
	medium: "allow",
	low: "allow",
	info: "allow"
};
/** The default action for a finding: its ID's entry in {@link DEFAULT_ACTIONS}, else by severity. */
function defaultAction(finding) {
	return Object.hasOwn(DEFAULT_ACTIONS, finding.id) ? DEFAULT_ACTIONS[finding.id] : BY_SEVERITY[finding.severity];
}
// ../packages/gate/src/policy/lists.ts
init_src$1();
const NAME_CHARS = /^(?:@[a-z0-9*?._~-]+\/)?[a-z0-9*?._~-]+$/i;
const VERSION_CHARS = /^[0-9A-Za-z.+-]+$/;
function globToRegExp(glob) {
	let src = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i];
		if (c === "*" && glob[i + 1] === "*") {
			src += ".*";
			i++;
		} else if (c === "*") src += "[^/]*";
		else if (c === "?") src += "[^/]";
		else src += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
	}
	return new RegExp(`^${src}$`);
}
function compile(entry, list) {
	const at = entry.indexOf("@", entry.startsWith("@") ? 1 : 0);
	const name = at < 0 ? entry : entry.slice(0, at);
	const version = at < 0 ? null : entry.slice(at + 1);
	if (!NAME_CHARS.test(name) || version !== null && !VERSION_CHARS.test(version)) throw new DepwardError("INVALID_CONFIG", `"${list}" entry ${JSON.stringify(entry)} must be a package name glob, optionally with an exact @version`);
	return {
		entry,
		name: globToRegExp(name),
		version
	};
}
/**
* Compiles a list of entries.
*
* @throws DepwardError `INVALID_CONFIG` for a malformed entry
*/
function compileList(entries, list) {
	const compiled = entries.map((e) => compile(e, list));
	return {
		match(name, version) {
			return compiled.find((c) => c.name.test(name) && (c.version === null || c.version === version))?.entry ?? null;
		},
		matchesName(name) {
			return compiled.find((c) => c.version === null && c.name.test(name))?.entry ?? null;
		}
	};
}
// ../packages/gate/src/policy/engine.ts
init_src$1();
const PAIRED = /* @__PURE__ */ new Set(["low-downloads", "package-too-new"]);
/**
* Compiles a config into a {@link Policy}.
*
* @throws DepwardError `INVALID_CONFIG` for a malformed `allow` or `deny` entry
*/
function createPolicy(config = defaultConfig()) {
	const allow = compileList(config.allow, "allow");
	const deny = compileList(config.deny, "deny");
	function decide(finding, present) {
		let action = defaultAction(finding);
		let source = "default";
		if ((PAIRED.has(finding.id) && present.has("low-downloads") && present.has("package-too-new") || finding.id === "install-script" && (present.has("low-downloads") || present.has("package-too-new")) || finding.severity === "critical") && action !== "deny") {
			action = "deny";
			source = "escalation";
		}
		const override = Object.hasOwn(config.policy, finding.id) ? config.policy[finding.id] : void 0;
		if (override !== void 0) {
			action = override;
			source = "config";
		}
		return {
			finding,
			action,
			source
		};
	}
	const listed = (name, version) => {
		const d = deny.match(name, version);
		if (d !== null) return {
			list: "deny",
			entry: d
		};
		const a = allow.match(name, version);
		return a === null ? null : {
			list: "allow",
			entry: a
		};
	};
	return {
		config,
		listed,
		deniedByName(name) {
			const d = deny.matchesName(name);
			return d === null ? null : {
				list: "deny",
				entry: d
			};
		},
		decideFindings(findings) {
			const present = new Set(findings.map((f) => f.id));
			return findings.map((f) => decide(f, present));
		},
		decidePackage({ name, version, findings, errors }) {
			const match = listed(name, version);
			const present = new Set(findings.map((f) => f.id));
			let decided = findings.map((f) => decide(f, present));
			if (match?.list === "allow") decided = decided.map((d) => ({
				...d,
				action: "allow",
				source: "allow-list"
			}));
			else if (match?.list === "deny") decided = [{
				finding: denylisted(name, version, match.entry, config.source),
				action: "deny",
				source: "deny-list"
			}, ...decided];
			const errorAction = errors.length > 0 && match?.list !== "allow" ? config.onError : null;
			return {
				action: strictest([...decided.map((d) => d.action), ...errorAction === null ? [] : [errorAction]]),
				findings: decided,
				errorAction,
				listed: match
			};
		}
	};
}
function denylisted(name, version, entry, source) {
	return {
		id: "denylisted",
		severity: "high",
		package: name,
		...version === null ? {} : { version },
		message: `${name} is on the config's deny list (${JSON.stringify(entry)}).`,
		evidence: [{ detail: `deny entry ${JSON.stringify(entry)}${source === null ? "" : ` in ${source}`}` }],
		docsUrl: findingDocsUrl("denylisted")
	};
}
// ../packages/gate/src/gate.ts
init_src$1();
// ../packages/gate/src/report.ts
init_src$1();
// ../packages/diff/src/lockfile/check.ts
init_src$1();
function toError(err) {
	return isDepwardError(err) ? err : new DepwardError("INTERNAL", "package check failed", { cause: err });
}
/** The highest severity, or `info`. */
function maxSeverity(findings) {
	return findings.map((f) => f.severity).toSorted(compareSeverity)[0] ?? "info";
}
/**
* `lockfile-integrity-mismatch` when the lockfile's integrity for a registry entry
* disagrees with the registry's `dist` for that version. `null` when they agree or have
* no hash algorithm in common.
*/
function integrityFinding(entry, meta, lockfile) {
	if (entry.integrity === null || compareIntegrity(entry.integrity, meta.dist) !== false) return null;
	return {
		id: "lockfile-integrity-mismatch",
		severity: "critical",
		package: entry.name,
		version: entry.version,
		message: `${lockfile} locks ${entry.name}@${entry.version} to a different tarball than the registry publishes for that version`,
		evidence: [
			{
				file: lockfile,
				snippet: escapeUnsafe(entry.integrity),
				detail: "lockfile integrity"
			},
			{
				snippet: escapeUnsafe(meta.dist.integrity ?? `sha1 ${meta.dist.shasum ?? "?"}`),
				detail: "registry integrity"
			},
			...entry.resolved === null ? [] : [{
				snippet: escapeUnsafe(entry.resolved),
				detail: "lockfile resolved URL"
			}]
		],
		docsUrl: findingDocsUrl("lockfile-integrity-mismatch")
	};
}
const tarballFindings = (fs) => fs.filter((f) => f.id.startsWith("tarball-"));
/**
* Diffs version `from` of a package against version `to`: both tarballs are analyzed
* (through the gate's tarball check and its analysis cache) and compared with
* `diffPackages`, using the packument for the publisher check. With `entry`, the
* lockfile's integrity for `to` is also checked against the registry.
*/
async function diffVersions(name, from, to, opts) {
	const result = {
		kind: "updated",
		name,
		from,
		to,
		lockfiles: opts.lockfile === void 0 ? [] : [opts.lockfile],
		findings: [],
		errors: [],
		risk: "info"
	};
	try {
		const packument = await opts.registry.packument(name);
		if (packument === null) throw new DepwardError("NOT_FOUND", `${name} is not in the registry`);
		const metaA = pickVersion(packument, from);
		const metaB = pickVersion(packument, to);
		for (const [v, m] of [[from, metaA], [to, metaB]]) if (m === null) result.errors.push(new DepwardError("NOT_FOUND", `${name}@${v} is not in the registry`));
		if (metaA === null || metaB === null) return result;
		const tarOpts = {
			registry: opts.registry,
			...opts.analysisCache === void 0 ? {} : { analysisCache: opts.analysisCache },
			...opts.tarLimits === void 0 ? {} : { tarLimits: opts.tarLimits },
			...opts.analyze === void 0 ? {} : { analyze: opts.analyze }
		};
		const [a, b] = await Promise.all([checkTarball(metaA, tarOpts), checkTarball(metaB, tarOpts)]);
		result.errors.push(...a.errors, ...b.errors);
		const findings = tarballFindings(b.findings);
		if (a.profile !== null && b.profile !== null) {
			const now = (opts.now ?? Date.now)();
			result.diff = diffPackages(a.profile, b.profile, metaA, metaB, {
				packument,
				now,
				...opts.isYoungDependency === void 0 ? {} : { isYoungDependency: opts.isYoungDependency }
			});
			findings.push(...result.diff.findings);
		}
		const mismatch = opts.entry ? integrityFinding(opts.entry, metaB, opts.lockfile ?? "lockfile") : null;
		if (mismatch) findings.push(mismatch);
		result.findings = sortFindings(findings);
		result.risk = diffRisk(result.findings);
	} catch (err) {
		result.errors.push(toError(err));
	}
	return result;
}
/**
* Runs the gate's registry and tarball checks on a lockfile entry that has no earlier
* version to compare with, plus the lockfile integrity check.
*/
async function checkNew(entry, kind, lockfile, opts) {
	const result = {
		kind,
		name: entry.name,
		to: entry.version,
		lockfiles: [lockfile],
		findings: [],
		errors: [],
		risk: "info"
	};
	try {
		const checked = await checkPackage({
			name: entry.name,
			range: entry.version
		}, {
			registry: opts.registry,
			...opts.data === void 0 ? {} : { data: opts.data },
			...opts.now === void 0 ? {} : { now: opts.now },
			...opts.analysisCache === void 0 ? {} : { analysisCache: opts.analysisCache },
			...opts.tarLimits === void 0 ? {} : { tarLimits: opts.tarLimits },
			...opts.analyze === void 0 ? {} : { analyze: opts.analyze }
		});
		result.errors.push(...checked.errors);
		const mismatch = checked.meta ? integrityFinding(entry, checked.meta, lockfile) : null;
		result.findings = sortFindings(mismatch ? [...checked.findings, mismatch] : checked.findings);
		result.risk = maxSeverity(result.findings);
	} catch (err) {
		result.errors.push(toError(err));
	}
	return result;
}
const SOURCE_NAMES = {
	git: "a git repository",
	tarball: "a tarball URL",
	other: "a non-npm source"
};
/** `non-registry-source` for an entry locked to git, a tarball URL, or another non-npm source. */
function nonRegistryResult(entry, lockfile) {
	const finding = {
		id: "non-registry-source",
		severity: "medium",
		package: entry.name,
		version: entry.version,
		message: `${lockfile} installs ${entry.name} from ${SOURCE_NAMES[entry.source] ?? "a non-npm source"}, not the npm registry, so depward can't check it`,
		evidence: [{
			file: lockfile,
			snippet: escapeUnsafe(entry.resolved ?? entry.version)
		}],
		docsUrl: findingDocsUrl("non-registry-source")
	};
	return {
		kind: "non-registry",
		name: entry.name,
		to: entry.version,
		lockfiles: [lockfile],
		findings: [finding],
		errors: [],
		risk: "medium"
	};
}
// ../packages/diff/src/lockfile/plan.ts
const NON_REGISTRY = /* @__PURE__ */ new Set([
	"git",
	"tarball",
	"other"
]);
const NUMS = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/;
/** Semver-ish comparison: numeric core, then a release sorts after its prereleases. Unparseable versions sort first. */
function compareVersions(a, b) {
	const x = NUMS.exec(a);
	const y = NUMS.exec(b);
	if (!x || !y) return x ? 1 : y ? -1 : a < b ? -1 : a > b ? 1 : 0;
	for (let i = 1; i <= 3; i++) {
		const d = Number(x[i]) - Number(y[i]);
		if (d !== 0) return d;
	}
	const pa = x[4];
	const pb = y[4];
	if (pa === pb) return 0;
	if (pa === void 0) return 1;
	if (pb === void 0) return -1;
	return pa < pb ? -1 : 1;
}
const major = (v) => NUMS.exec(v)?.[1];
/**
* Pairs removed and added registry entries of the same name into updates. Each added
* version (lowest first) takes the highest unused removed version with the same major,
* else the highest unused removed version. Added entries left over are new packages.
*/
function planLockfile(diff) {
	const plan = {
		updates: [],
		checks: [],
		nonRegistry: [],
		skipped: []
	};
	const removedByName = /* @__PURE__ */ new Map();
	for (const e of diff.removed) {
		if (e.source !== "registry") continue;
		const list = removedByName.get(e.name) ?? [];
		list.push(e);
		removedByName.set(e.name, list);
	}
	for (const list of removedByName.values()) list.sort((a, b) => compareVersions(b.version, a.version));
	const added = diff.added.toSorted((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : compareVersions(a.version, b.version));
	for (const entry of added) {
		if (entry.source !== "registry") {
			route(plan, {
				kind: "added",
				entry
			});
			continue;
		}
		const pool = removedByName.get(entry.name) ?? [];
		let i = pool.findIndex((r) => major(r.version) === major(entry.version));
		if (i < 0 && pool.length > 0) i = 0;
		const before = i >= 0 ? pool.splice(i, 1)[0] : void 0;
		if (before) plan.updates.push({
			before,
			after: entry
		});
		else plan.checks.push({
			kind: "added",
			entry
		});
	}
	for (const { before, after } of diff.changed) {
		if (after.source === before.source && (after.integrity === null || before.integrity === null || after.integrity === before.integrity)) continue;
		route(plan, {
			kind: "changed",
			entry: after
		});
	}
	return plan;
}
function route(plan, check) {
	if (check.entry.source === "registry") plan.checks.push(check);
	else if (NON_REGISTRY.has(check.entry.source)) plan.nonRegistry.push(check);
	else plan.skipped.push(check.entry);
}
// ../packages/diff/src/lockfile/locate.ts
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
/** At most this many occurrences of a name are examined per lookup. */
const MAX_CANDIDATES = 1e4;
/**
* Returns a lookup `(name, version) => line` over one lockfile's text. The text is
* indexed once, so many lookups stay cheap. Lines are 1-based.
*
* Recognized shapes, tried in this order:
* - a key that names the exact version: pnpm `name@1.2.3:` / `/name@1.2.3:` /
*   `/name/1.2.3:`, bun `"name@1.2.3"`;
* - a header followed within three lines by its version: npm `"node_modules/name": {`
*   then `"version": "1.2.3"`, yarn `name@^1.0.0:` then `version "1.2.3"`.
*/
function lockfileLocator(text) {
	const starts = [0];
	for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
	const lineAt = (offset) => {
		let lo = 0;
		let hi = starts.length - 1;
		while (lo < hi) {
			const mid = lo + hi + 1 >> 1;
			if ((starts[mid] ?? 0) <= offset) lo = mid;
			else hi = mid - 1;
		}
		return lo;
	};
	const lineText = (i) => {
		const end = i + 1 < starts.length ? (starts[i + 1] ?? text.length) - 1 : text.length;
		const s = text.slice(starts[i] ?? 0, end);
		return s.endsWith("\r") ? s.slice(0, -1) : s;
	};
	return (name, version) => {
		if (name === "" || version === "") return void 0;
		const candidates = [];
		for (let at = text.indexOf(name); at !== -1 && candidates.length < MAX_CANDIDATES; at = text.indexOf(name, at + name.length)) {
			const l = lineAt(at);
			if (candidates.at(-1) !== l) candidates.push(l);
		}
		const n = escapeRegExp(name);
		const v = escapeRegExp(version);
		const direct = new RegExp(`(?:^\\s*|["'\\[]\\s*)["']?/?${n}@${v}(?=[\\s"':(_,]|$)|^\\s*/${n}/${v}(?=[\\s"':(_]|$)`);
		for (const l of candidates) if (direct.test(lineText(l))) return l + 1;
		const header = new RegExp(`node_modules/${n}"|(?:^|[\\s"',])${n}@`);
		const versionLine = new RegExp(`version.*(?<![\\w.+-])${v}(?![\\w.+-])`);
		for (const l of candidates) {
			if (!header.test(lineText(l))) continue;
			for (let j = l + 1; j <= l + 3 && j < starts.length; j++) {
				const t = lineText(j);
				if (t.trim() === "" || !/^\s/.test(t) || t.includes("node_modules/")) break;
				if (versionLine.test(t)) return l + 1;
			}
		}
	};
}
// ../packages/diff/src/lockfile/policy.ts
init_src$1();
/** Severities `--fail-on` accepts, plus `none` (never fail). */
const FAIL_ON_LEVELS = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
	"none"
];
/** Returns `result` with the config's policy applied (see the module comment). Pure. */
function applyPolicy(result, policy) {
	const match = policy.listed(result.name, result.to);
	const verdict = policy.decidePackage({
		name: result.name,
		version: result.to,
		findings: result.findings,
		errors: []
	});
	const counted = match?.list === "allow" ? [] : verdict.findings.filter((d) => d.source !== "config" || d.action !== "allow").map((d) => d.finding);
	const allowed = verdict.findings.map((d) => d.finding).filter((f) => !counted.includes(f));
	let risk = result.kind === "updated" ? diffRisk(counted) : maxSeverity(counted);
	if (match?.list === "deny") risk = "critical";
	return {
		...result,
		findings: sortFindings(counted),
		allowedFindings: sortFindings([...result.allowedFindings ?? [], ...allowed]),
		listed: match,
		risk
	};
}
/**
* True when a package's risk reaches `failOn`. Packages without counted findings never
* fail (their risk is only `info` by default), so `--fail-on info` means "any finding".
*/
function reachesFailOn(packages, failOn) {
	if (failOn === "none") return false;
	return packages.some((p) => (p.findings.length > 0 || p.listed?.list === "deny") && compareSeverity(p.risk, failOn) <= 0);
}
// ../packages/diff/src/lockfile/run.ts
init_src$1();
/** Runs `fn` over `items` with at most `limit` calls in flight; results keep input order. */
async function mapLimit(items, limit, fn) {
	const out = Array.from({ length: items.length });
	let next = 0;
	const worker = async () => {
		while (next < items.length) {
			const i = next++;
			out[i] = await fn(items[i]);
		}
	};
	await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
	return out;
}
async function resolveBase$1(opts) {
	const ref = opts.base ?? "origin/HEAD";
	try {
		return await mergeBase(ref, opts.cwd);
	} catch (err) {
		if (opts.base === void 0 && isDepwardError(err, "GIT")) throw new DepwardError("GIT", `${err.message}; pass --base <ref> (for example origin/main)`, { cause: err });
		throw err;
	}
}
async function readWorkingTree(path) {
	try {
		return await readFile(path, "utf8");
	} catch (err) {
		if (err.code === "ENOENT") return null;
		throw new DepwardError("INVALID_ARGUMENT", `cannot read ${path}`, { cause: err });
	}
}
const empty = (path) => ({
	path,
	format: null,
	entries: /* @__PURE__ */ new Map(),
	findings: []
});
const key = (name, version) => `${name}@${version}`;
function remember(map, k, value, lockfile) {
	const seen = map.get(k);
	if (seen) seen.lockfiles.push(lockfile);
	else map.set(k, {
		...value,
		lockfiles: [lockfile]
	});
}
/**
* Compares the lockfiles in `opts.cwd` (working tree, or `opts.head`) with the same
* files at the merge-base of `HEAD` and `opts.base`. Version updates are diffed with
* {@link diffPackages}; new packages go through the gate's registry and tarball checks;
* git and tarball-URL entries are reported as `non-registry-source`. The same change in
* several lockfiles is checked once.
*
* @throws DepwardError `GIT` (no repository, unknown ref, no common history),
*   `INVALID_LOCKFILE`, `LIMIT_EXCEEDED` (more than `maxPackages` to check).
*/
async function diffLockfile(opts) {
	const base = await resolveBase$1(opts);
	const lockfiles = [];
	const locators = /* @__PURE__ */ new Map();
	const work = {
		updates: /* @__PURE__ */ new Map(),
		checks: /* @__PURE__ */ new Map(),
		nonRegistry: /* @__PURE__ */ new Map(),
		skipped: /* @__PURE__ */ new Set()
	};
	const atBase = new Set(await filesAtRef(base, KNOWN_LOCKFILES, opts.cwd));
	const atHead = opts.head === void 0 ? null : new Set(await filesAtRef(opts.head, KNOWN_LOCKFILES, opts.cwd));
	for (const name of KNOWN_LOCKFILES) {
		let headText = null;
		if (atHead === null) headText = await readWorkingTree(join(opts.cwd, name));
		else if (opts.head !== void 0 && atHead.has(name)) headText = await readFileAtRef(opts.head, name, opts.cwd);
		const baseText = atBase.has(name) ? await readFileAtRef(base, name, opts.cwd) : null;
		if (headText === null && baseText === null) continue;
		const head = headText === null ? empty(name) : parseLockfile(name, headText);
		if (headText !== null) locators.set(name, lockfileLocator(headText));
		const before = baseText === null ? empty(name) : parseLockfile(name, baseText);
		const diff = diffLockfiles(before, head);
		lockfiles.push({
			path: name,
			format: head.format ?? before.format,
			counts: {
				added: diff.added.length,
				removed: diff.removed.length,
				changed: diff.changed.length
			},
			findings: head.findings
		});
		const plan = planLockfile(diff);
		for (const u of plan.updates) remember(work.updates, `${key(u.before.name, u.before.version)}>${u.after.version}`, u, name);
		for (const c of plan.checks) remember(work.checks, key(c.entry.name, c.entry.version), c, name);
		for (const c of plan.nonRegistry) remember(work.nonRegistry, key(c.entry.name, c.entry.version), c, name);
		for (const e of plan.skipped) work.skipped.add(key(e.name, e.version));
	}
	const total = work.updates.size + work.checks.size;
	const max = opts.maxPackages ?? 1e3;
	if (total > max) throw new DepwardError("LIMIT_EXCEEDED", `${total} packages changed, more than the limit of ${max}`);
	const limit = opts.concurrency ?? 8;
	const checked = await mapLimit([...work.checks.values()], limit, async (c) => ({
		...await checkNew(c.entry, c.kind, c.lockfiles[0] ?? "", opts),
		lockfiles: c.lockfiles
	}));
	const young = new Set(checked.filter((r) => r.findings.some((f) => f.id === "package-too-new")).map((r) => r.name));
	const updated = await mapLimit([...work.updates.values()], limit, async (u) => ({
		...await diffVersions(u.after.name, u.before.version, u.after.version, {
			...opts,
			entry: u.after,
			lockfile: u.lockfiles[0] ?? "",
			isYoungDependency: (n) => young.has(n)
		}),
		lockfiles: u.lockfiles
	}));
	const external = [...work.nonRegistry.values()].map((c) => ({
		...nonRegistryResult(c.entry, c.lockfiles[0] ?? ""),
		lockfiles: c.lockfiles
	}));
	const policy = opts.policy;
	const results = [
		...updated,
		...checked,
		...external
	].map((r) => {
		const line = locators.get(r.lockfiles[0] ?? "")?.(r.name, r.to);
		return line === void 0 ? r : {
			...r,
			line
		};
	});
	const packages = (policy === void 0 ? results : results.map((r) => applyPolicy(r, policy))).toSorted(comparePackages);
	const findings = sortFindings([...lockfiles.flatMap((l) => l.findings), ...packages.flatMap((p) => p.findings)]);
	return {
		base,
		head: opts.head ?? null,
		lockfiles,
		packages,
		skipped: [...work.skipped].toSorted(),
		findings,
		risk: packages.map((p) => p.risk).toSorted(compareSeverity)[0] ?? "info"
	};
}
function comparePackages(a, b) {
	return compareSeverity(a.risk, b.risk) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || (a.to < b.to ? -1 : a.to > b.to ? 1 : 0);
}
// ../packages/diff/src/index.ts
/** The version of `@depward/diff`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
const VERSION = "0.0.0";
// ../packages/cli/src/context.ts
init_src$1();
/** Loads the config and opens the registry client, honouring `--config` and `--offline`. */
async function openContext(rt, args) {
	const config = await loadConfig(rt.cwd, args.config === void 0 ? {} : { path: args.config });
	const cache = createDiskCache(defaultCacheDir(rt.env));
	return {
		config,
		registry: rt.gate?.registry ?? createRegistryClient({
			cwd: rt.cwd,
			env: rt.env,
			cache,
			...config.registry === void 0 ? {} : { registry: config.registry },
			...args.offline ? { offline: true } : {}
		}),
		analysisCache: rt.gate?.registry ? void 0 : cache,
		overrides: rt.gate ?? {}
	};
}
// ../packages/cli/src/diff-markdown.ts
init_src$1();
const ICON = {
	critical: "🔴",
	high: "🟠",
	medium: "🟡",
	low: "🔵",
	info: "⚪"
};
const LABEL = {
	"diff-new-install-script": "new install script",
	"diff-new-capability": "new capability",
	"diff-new-network-in-non-network-pkg": "new network",
	"diff-new-sensitive-env": "new secret read",
	"diff-new-endpoint": "new endpoint",
	"diff-new-obfuscation": "new obfuscation",
	"diff-new-dependency": "new dependency",
	"diff-publisher-changed": "publisher changed",
	"diff-provenance-dropped": "provenance dropped",
	"diff-semver-mismatch": "semver mismatch",
	"lockfile-integrity-mismatch": "integrity mismatch",
	"non-registry-source": "non-registry source",
	denylisted: "deny-listed"
};
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const code = (s, max) => `<code>${escapeMarkdown(s, max)}</code>`;
/** A docs link, only for https URLs; anything else is plain text. */
function docsLink(f) {
	const label = code(f.id, 80);
	if (!/^https:\/\/[^\s<>"'()]+$/.test(f.docsUrl)) return label;
	return `<a href="${encodeURI(f.docsUrl).replace(/"/g, "%22")}">${label}</a>`;
}
function changeText(p) {
	if (p.from !== void 0) return `${escapeMarkdown(p.from, 60)} → ${escapeMarkdown(p.to, 60)}`;
	return `${p.kind} ${escapeMarkdown(p.to, 100)}`;
}
/** Whether the package gets its own row and section (the rest are listed, collapsed). */
const flagged = (p) => p.findings.some((f) => f.severity !== "info") || p.errors.length > 0 || p.listed?.list === "deny";
function why(p) {
	const labels = [...new Set(p.findings.filter((f) => f.severity !== "info").map((f) => LABEL[f.id] ?? f.id))];
	if (p.listed?.list === "deny" && !labels.includes("deny-listed")) labels.unshift("deny-listed");
	if (p.errors.length > 0) labels.push("lookup failed");
	const shown = labels.slice(0, 4).map((l) => escapeMarkdown(l, 60));
	return labels.length > 4 ? `${shown.join(" · ")} · +${labels.length - 4} more` : shown.join(" · ");
}
function findingLines(f, maxEvidence, allowed) {
	const out = [`- **${allowed ? "allowed" : f.severity}** ${docsLink(f)}: ${escapeMarkdown(f.message, 300)}`];
	for (const e of f.evidence.slice(0, maxEvidence)) {
		const loc = e.file === void 0 ? void 0 : e.line !== void 0 && e.line > 0 ? `${e.file}:${e.line}` : e.file;
		const line = [
			loc === void 0 ? void 0 : code(loc, 200),
			e.snippet === void 0 ? void 0 : code(e.snippet, 200),
			e.detail === void 0 ? void 0 : escapeMarkdown(e.detail, 200)
		].filter((x) => x !== void 0).join(" ");
		if (line) out.push(`  - ${line}`);
	}
	if (f.evidence.length > maxEvidence) out.push(`  - _and ${f.evidence.length - maxEvidence} more_`);
	return out;
}
/** One collapsible section. High and critical start open; lower risks start collapsed. */
function packageSection(p, maxEvidence) {
	const open = compareSeverity(p.risk, "high") <= 0 ? " open" : "";
	const label = p.from === void 0 ? `${p.name}@${p.to}` : `${p.name} ${p.from} → ${p.to}`;
	const out = [`<details${open}><summary>${ICON[p.risk]} <b>${p.risk}</b> · ${code(label, 240)} (${p.kind})</summary>`, ""];
	if (p.lockfiles.length > 0) out.push(`In ${p.lockfiles.map((l) => code(l, 200)).join(", ")}${p.line === void 0 ? "" : ` (line ${p.line})`}.`, "");
	if (p.listed) out.push(`On the config's **${p.listed.list}** list.`, "");
	for (const f of p.findings) out.push(...findingLines(f, maxEvidence, false));
	for (const e of p.errors) out.push(`- **lookup failed** ${code(e.code, 40)}: ${escapeMarkdown(e.message, 300)}`);
	const allowed = p.allowedFindings ?? [];
	if (allowed.length > 0) {
		out.push("", `Allowed by the project config (not counted):`, "");
		for (const f of allowed) out.push(...findingLines(f, maxEvidence, true));
	}
	out.push("", "</details>");
	return out.join("\n");
}
function quietSection(packages) {
	const items = packages.map((p) => {
		const allowed = p.allowedFindings?.length ?? 0;
		return `- ${code(p.name, 214)} ${changeText(p)}${allowed === 0 ? "" : ` · ${plural(allowed, "allowed finding")}`}`;
	});
	return [
		`<details><summary>${plural(packages.length, "package change")} with no findings</summary>`,
		"",
		...items,
		"",
		"</details>"
	].join("\n");
}
/**
* Renders a diff as GitHub-flavored Markdown: a heading, a summary table of packages
* with findings, one collapsible section per such package (evidence with file:line and
* snippets), then collapsed lists of quiet and skipped packages. Output fits in
* `maxLength`; sections that don't fit are dropped with a note.
*/
function renderDiffMarkdown(view, opts = {}) {
	const maxLength = opts.maxLength ?? 6e4;
	const maxEvidence = opts.maxEvidence ?? 5;
	const n = view.packages.length;
	const shown = view.packages.filter(flagged);
	const quiet = view.packages.filter((p) => !flagged(p));
	const review = view.packages.filter((p) => compareSeverity(p.risk, "medium") <= 0 || p.errors.length > 0);
	const heading = `## depward: ${plural(n, "dependency change")}${review.length > 0 ? `, ${review.length} need${review.length === 1 ? "s" : ""} review` : ""}`;
	const head = opts.marker === void 0 ? [heading, ""] : [
		opts.marker,
		heading,
		""
	];
	if (view.base !== null) {
		const target = view.head === null ? "the working tree" : code(view.head, 100);
		head.push(`Compared with ${code(view.base.slice(0, 12), 12)} (merge-base) → ${target}.`, "");
	}
	const notes = view.lockfiles.flatMap((l) => l.findings.map((f) => `- ${ICON[f.severity]} ${code(l.path, 200)}: ${escapeMarkdown(f.message, 300)}`));
	if (notes.length > 0) head.push(...notes, "");
	if (n === 0) return `${head.join("\n").trimEnd()}\n`;
	if (shown.length === 0) head.push("No findings.", "");
	const rows = shown.map((p) => `| ${ICON[p.risk]} ${p.risk} | ${code(p.name, 214)} | ${changeText(p)} | ${why(p)} |`);
	const sections = shown.map((p) => packageSection(p, maxEvidence));
	const allowedCount = view.packages.reduce((sum, p) => sum + (p.allowedFindings?.length ?? 0), 0);
	const tail = [];
	if (allowedCount > 0) tail.push(`_${allowedCount === 1 ? "1 finding is" : `${allowedCount} findings are`} allowed by the project config and not counted._`);
	if (quiet.length > 0) tail.push(quietSection(quiet));
	if (view.skipped.length > 0) {
		const items = view.skipped.map((s) => `- ${code(s, 214)}`);
		tail.push([
			`<details><summary>${plural(view.skipped.length, "entry")} skipped (local or bundled)</summary>`,
			"",
			...items,
			"",
			"</details>"
		].join("\n"));
	}
	const note = (rowCount, blocks) => `> [!NOTE]\n> The report did not fit in one comment: ${plural(rowCount, "table row")} and ${plural(blocks, "package section")} left out. Run \`depward diff --lockfile\` locally, or see the SARIF or JSON output, for the full report.`;
	const budget = maxLength - note(99999, 99999).length - 2;
	const out = [...head];
	let size = head.join("\n").length + 1;
	let droppedRows = 0;
	if (rows.length > 0) {
		const table = ["| Risk | Package | Change | Why |", "|---|---|---|---|"];
		let tableSize = table.join("\n").length;
		const more = (k) => `| … | | | +${plural(k, "more package")} |`;
		for (const [i, r] of rows.entries()) {
			const reserve = i === rows.length - 1 ? 0 : more(rows.length).length + 1;
			if (tableSize + r.length + 1 + reserve > budget / 2) {
				droppedRows = rows.length - i;
				table.push(more(droppedRows));
				break;
			}
			table.push(r);
			tableSize += r.length + 1;
		}
		out.push(table.join("\n"), "");
		size += table.join("\n").length + 2;
	}
	let droppedBlocks = 0;
	for (const block of [...sections, ...tail]) if (droppedBlocks === 0 && size + block.length + 2 <= budget) {
		out.push(block, "");
		size += block.length + 2;
	} else droppedBlocks++;
	if (droppedRows > 0 || droppedBlocks > 0) out.push(note(droppedRows, droppedBlocks), "");
	return `${out.join("\n").trimEnd()}\n`;
}
// ../packages/cli/src/diff-render.ts
init_src$1();
const SGR = {
	critical: "1;31",
	high: "31",
	medium: "33",
	low: "36",
	info: "2"
};
/** `name from → to` or `name@to`. */
function changeLabel(p) {
	return p.from === void 0 ? `${p.name}@${p.to}` : `${p.name} ${p.from} → ${p.to}`;
}
function counts(packages) {
	const n = packages.length;
	if (n === 0) return "no dependency changes";
	const parts = SEVERITIES.map((s) => [s, packages.filter((p) => p.risk === s).length]).filter(([, c]) => c > 0).map(([s, c]) => `${c} ${s}`);
	return `${n} package change${n === 1 ? "" : "s"}: ${parts.join(", ")}`;
}
const errorLine = (e) => `${e.code}: ${e.message}`;
/** The terminal view. Packages without findings are counted, not listed, unless `verbose`. */
function renderDiffTerminal(view, opts = {}) {
	const paint = (sgr, s) => opts.color ? `\u001b[${sgr}m${s}\u001b[0m` : s;
	const lines = [`depward diff: ${paint(SGR[view.risk], view.risk)} (${counts(view.packages)})`];
	if (view.base !== null) lines.push(`base ${view.base.slice(0, 12)}, head ${view.head === null ? "working tree" : escapeUnsafe(view.head, 100)}`);
	for (const l of view.lockfiles) for (const f of l.findings) lines.push(`${escapeUnsafe(l.path, 200)}: ${escapeUnsafe(f.message, 300)}`);
	let hidden = 0;
	let allowedHidden = 0;
	const findingLines = (f, allowed) => {
		const out = [`            ${paint("1", escapeUnsafe(f.id, 80))} [${allowed ? "allowed" : f.severity}]: ${escapeUnsafe(f.message, 300)}`];
		const where = f.evidence.find((e) => e.file !== void 0);
		if (where?.file !== void 0) out.push(`              at ${escapeUnsafe(where.file, 200)}${where.line === void 0 ? "" : `:${where.line}`}`);
		return out;
	};
	for (const p of view.packages) {
		const shown = opts.verbose ? p.findings : p.findings.filter((f) => f.severity !== "info");
		const allowed = p.allowedFindings ?? [];
		if (!opts.verbose) allowedHidden += allowed.length;
		if (shown.length === 0 && p.errors.length === 0 && p.listed?.list !== "deny" && !opts.verbose) {
			hidden++;
			continue;
		}
		lines.push("", `  ${paint(SGR[p.risk], p.risk.toUpperCase().padEnd(8))}  ${escapeUnsafe(changeLabel(p), 200)}  (${p.kind})`);
		if (p.listed) lines.push(`            on the config's ${p.listed.list} list (${escapeUnsafe(JSON.stringify(p.listed.entry), 200)})`);
		for (const f of shown) lines.push(...findingLines(f, false));
		if (opts.verbose) for (const f of allowed) lines.push(...findingLines(f, true));
		for (const e of p.errors) lines.push(`            ${paint("1", "lookup failed")}: ${escapeUnsafe(errorLine(e), 300)}`);
	}
	if (hidden > 0) lines.push("", `${hidden} package change${hidden === 1 ? "" : "s"} with no findings not shown (--verbose shows them).`);
	if (allowedHidden > 0) lines.push(`${allowedHidden} finding${allowedHidden === 1 ? "" : "s"} allowed by the config not shown (--verbose shows them).`);
	if (opts.verbose && view.skipped.length > 0) lines.push("", `skipped (local or bundled): ${view.skipped.map((s) => escapeUnsafe(s, 200)).join(", ")}`);
	return `${lines.join("\n")}\n`;
}
/**
* SARIF, with each finding located at its package's entry in the lockfile it came from
* (line 1 when the entry wasn't found), so GitHub can show it on the PR's changed lines.
* Lockfile-level findings point at their lockfile; anything else at `package.json`.
*/
function renderDiffSarif(view, tool) {
	const where = /* @__PURE__ */ new Map();
	for (const p of view.packages) {
		const loc = {
			uri: p.lockfiles[0] ?? "package.json",
			line: p.line ?? 1
		};
		where.set(`${p.name} ${p.to}`, loc);
		if (!where.has(p.name)) where.set(p.name, loc);
	}
	const lockfilePaths = new Set(view.lockfiles.map((l) => l.path));
	return renderSarif(view.findings, {
		tool,
		locate: (f) => where.get(`${f.package} ${f.version ?? ""}`) ?? where.get(f.package) ?? {
			uri: lockfilePaths.has(f.package) ? f.package : "package.json",
			line: 1
		}
	});
}
// ../packages/cli/src/diff.ts
init_src$1();
/**
* Runs the diff (lockfile mode, or one package from `positionals`) with the project
* config applied, and returns the view every renderer takes. Shared by `depward diff`
* and the GitHub Action (action/).
*/
async function computeDiff(args, rt) {
	const { config, registry, analysisCache, overrides } = await openContext(rt, args);
	const policy = createPolicy(config);
	const opts = {
		registry,
		policy,
		...analysisCache === void 0 ? {} : { analysisCache },
		...overrides.data === void 0 ? {} : { data: overrides.data },
		...overrides.now === void 0 ? {} : { now: overrides.now }
	};
	let view;
	if (args.lockfile) view = { ...await diffLockfile({
		...opts,
		cwd: rt.cwd,
		concurrency: args.concurrency,
		...args.base === void 0 ? {} : { base: args.base },
		...args.head === void 0 ? {} : { head: args.head }
	}) };
	else {
		const [name, from, to] = args.positionals;
		const result = applyPolicy(await diffVersions(name, from, to, opts), policy);
		view = {
			packages: [result],
			findings: sortFindings(result.findings),
			risk: result.risk,
			lockfiles: [],
			skipped: [],
			base: null,
			head: null
		};
	}
	return {
		view,
		configSource: config.source
	};
}
// src/env.ts
init_src$1();
/** The raw value of an input, trimmed. Empty when unset. */
function getInput(env, name) {
	return (env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();
}
/** A boolean input: `true` or `false` (any case). Empty gives `fallback`. */
function getBooleanInput(env, name, fallback) {
	const v = getInput(env, name).toLowerCase();
	if (v === "") return fallback;
	if (v === "true") return true;
	if (v === "false") return false;
	throw new DepwardError("INVALID_ARGUMENT", `input ${name} must be true or false`);
}
const escapeData = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escapeProperty = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
/**
* A {@link Log} that writes workflow commands to `write`. Messages may contain package
* text, so controls are made visible first; that also stops a message from starting a
* workflow command of its own on a new line.
*/
function createLog(write) {
	return {
		info: (message) => {
			for (const line of message.split("\n")) write(line.startsWith("::") ? ` ${line}` : line);
		},
		annotate: (level, message, title) => {
			write(`::${level}${title === void 0 ? "" : ` title=${escapeProperty(escapeUnsafe(title, 200))}`}::${escapeData(escapeUnsafe(message, 2e3))}`);
		}
	};
}
/** Appends `name=value` outputs to the `GITHUB_OUTPUT` file. A no-op when it's unset. */
async function setOutputs(env, outputs) {
	const file = env["GITHUB_OUTPUT"];
	if (file === void 0 || file === "") return;
	let text = "";
	for (const [name, value] of Object.entries(outputs)) if (!value.includes("\n")) text += `${name}=${value}\n`;
	else {
		const delimiter = `ghadelimiter_${randomUUID()}`;
		text += `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
	}
	await appendFile(file, text, "utf8");
}
/** Appends Markdown to the job summary. Returns false when `GITHUB_STEP_SUMMARY` is unset. */
async function appendSummary(env, markdown) {
	const file = env["GITHUB_STEP_SUMMARY"];
	if (file === void 0 || file === "") return false;
	if (Buffer.byteLength(markdown, "utf8") > 1e6) throw new DepwardError("LIMIT_EXCEEDED", "the report is larger than the job summary limit");
	await appendFile(file, `${markdown}\n`, "utf8");
	return true;
}
// src/github.ts
init_src$1();
const gzip$1 = promisify(gzip);
/** REST API version sent with every request. */
const API_VERSION = "2026-03-10";
/** Per-request timeout. */
const REQUEST_TIMEOUT_MS = 15e3;
/** A non-2xx response. `status` tells a missing permission (403) from other failures. */
var GitHubApiError = class extends DepwardError {
	name = "GitHubApiError";
	status;
	constructor(status, message) {
		super("NETWORK", message);
		this.status = status;
	}
};
const toComment = (raw) => {
	const c = raw;
	if (typeof c.id !== "number") throw new DepwardError("INVALID_RESPONSE", "comment without an id");
	return {
		id: c.id,
		body: typeof c.body === "string" ? c.body : "",
		htmlUrl: typeof c.html_url === "string" ? c.html_url : "",
		userType: typeof c.user?.type === "string" ? c.user.type : ""
	};
};
/** A {@link GitHub} over the REST API. */
function createGitHub(opts) {
	const apiUrl = (opts.apiUrl ?? "https://api.github.com").replace(/\/+$/, "");
	if (!/^https:\/\/[^\s/]+/.test(apiUrl)) throw new DepwardError("INVALID_ARGUMENT", "the GitHub API URL must use https");
	if (!/^[\w.-]+\/[\w.-]+$/.test(opts.repository)) throw new DepwardError("INVALID_ARGUMENT", "GITHUB_REPOSITORY must be owner/name");
	const doFetch = opts.fetch ?? globalThis.fetch;
	async function call(method, path, body) {
		let res;
		try {
			res = await doFetch(`${apiUrl}/repos/${opts.repository}${path}`, {
				method,
				headers: {
					accept: "application/vnd.github+json",
					authorization: `Bearer ${opts.token}`,
					"x-github-api-version": API_VERSION,
					"user-agent": "depward-action",
					...body === void 0 ? {} : { "content-type": "application/json" }
				},
				...body === void 0 ? {} : { body: JSON.stringify(body) },
				signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
			});
		} catch (err) {
			const timeout = err instanceof Error && err.name === "TimeoutError";
			throw new DepwardError(timeout ? "TIMEOUT" : "NETWORK", `${method} ${path} ${timeout ? "timed out" : "failed"}`, { cause: err });
		}
		if (!res.ok) {
			const detail = await res.text().then((t) => t.slice(0, 300), () => "");
			throw new GitHubApiError(res.status, `${method} ${path}: HTTP ${res.status} ${detail}`.trim());
		}
		return res.status === 204 ? null : res.json();
	}
	return {
		async listComments(issue) {
			const out = [];
			for (let page = 1; page <= 10; page++) {
				const list = await call("GET", `/issues/${issue}/comments?per_page=100&page=${page}`);
				if (!Array.isArray(list)) throw new DepwardError("INVALID_RESPONSE", "comment list is not an array");
				out.push(...list.map(toComment));
				if (list.length < 100) break;
			}
			return out;
		},
		createComment: async (issue, body) => toComment(await call("POST", `/issues/${issue}/comments`, { body })),
		updateComment: async (id, body) => toComment(await call("PATCH", `/issues/comments/${id}`, { body })),
		async uploadSarif({ sarif, commitSha, ref, toolName }) {
			const res = await call("POST", "/code-scanning/sarifs", {
				commit_sha: commitSha,
				ref,
				sarif: (await gzip$1(Buffer.from(sarif, "utf8"))).toString("base64"),
				tool_name: toolName
			});
			return typeof res?.id === "string" ? res.id : "";
		}
	};
}
/**
* Updates the bot comment whose body starts with `marker`, or creates one. Only
* comments by a bot account are considered, so a user who pastes the marker can't make
* the Action edit their comment. With `createIfMissing: false` (nothing to report),
* an existing comment is still updated but no new one is posted.
*/
async function upsertStickyComment(gh, issue, marker, body, opts) {
	const existing = (await gh.listComments(issue)).find((c) => c.userType === "Bot" && c.body.startsWith(marker));
	if (existing !== void 0) return {
		action: "updated",
		url: (await gh.updateComment(existing.id, body)).htmlUrl
	};
	if (!opts.createIfMissing) return { action: "skipped" };
	return {
		action: "created",
		url: (await gh.createComment(issue, body)).htmlUrl
	};
}
// src/run.ts
init_src$1();
/** First line of the sticky comment. Changing it orphans existing comments. */
const COMMENT_MARKER = "<!-- depward-diff -->";
/** Reads and validates the inputs declared in action.yml. */
function readInputs(env) {
	const failOn = getInput(env, "fail-on") || "critical";
	if (!FAIL_ON_LEVELS.includes(failOn)) throw new DepwardError("INVALID_ARGUMENT", `input fail-on must be one of ${FAIL_ON_LEVELS.join(", ")}`);
	return {
		failOn,
		comment: getBooleanInput(env, "comment", true),
		sarif: getBooleanInput(env, "sarif", true),
		base: getInput(env, "base"),
		token: getInput(env, "github-token")
	};
}
const ZERO_SHA = /^0+$/;
/** Reads the run context from the environment and the event payload. */
async function readContext(env, readEvent = (p) => readFile(p, "utf8")) {
	const path = env["GITHUB_EVENT_PATH"];
	let event = {};
	if (path) try {
		event = JSON.parse(await readEvent(path));
	} catch (err) {
		throw new DepwardError("INVALID_ARGUMENT", "cannot read the event payload", { cause: err });
	}
	const pr = event["pull_request"];
	const repo = env["GITHUB_REPOSITORY"] ?? "";
	const headRepo = pr?.head?.repo?.full_name;
	const before = typeof event["before"] === "string" && !ZERO_SHA.test(event["before"]) ? event["before"] : void 0;
	return {
		eventName: env["GITHUB_EVENT_NAME"] ?? "",
		pr: typeof pr?.number === "number" ? pr.number : void 0,
		fromFork: pr !== void 0 && headRepo !== repo,
		baseRef: typeof pr?.base?.ref === "string" ? pr.base.ref : env["GITHUB_BASE_REF"] || void 0,
		before,
		sha: env["GITHUB_SHA"] ?? "",
		ref: env["GITHUB_REF"] ?? ""
	};
}
/** The git ref to compare with: the input, else the PR's base branch, else the commit before a push. */
function resolveBase(inputs, ctx) {
	if (inputs.base !== "") return inputs.base;
	if (ctx.pr !== void 0 && ctx.baseRef !== void 0) return `origin/${ctx.baseRef}`;
	if (ctx.before !== void 0) return ctx.before;
	throw new DepwardError("INVALID_ARGUMENT", `cannot tell what to compare with (event: ${ctx.eventName || "none"}); set the base input`);
}
/** Runs the Action. Returns 0 when the step passes, 1 when it fails. */
async function runAction(deps) {
	const { env, log } = deps;
	const inputs = readInputs(env);
	const ctx = await readContext(env, deps.readEvent);
	const base = resolveBase(inputs, ctx);
	log.info(`depward diff: comparing the lockfiles with ${base} (fail-on ${inputs.failOn})`);
	const view = await deps.computeView(base);
	const tool = {
		name: "depward",
		version: deps.version
	};
	log.info(renderDiffTerminal(view, { color: false }));
	const markdown = renderDiffMarkdown(view, { marker: COMMENT_MARKER });
	const sarif = renderDiffSarif(view, tool);
	const outputs = {
		risk: view.risk,
		changes: String(view.packages.length)
	};
	const tmp = env["RUNNER_TEMP"];
	if (tmp) {
		const file = join(tmp, "depward-diff.sarif");
		await writeFile(file, sarif, "utf8");
		outputs["sarif-file"] = file;
	}
	const gh = inputs.token === "" ? void 0 : deps.github(inputs.token);
	const readOnly = ctx.fromFork ? "the pull request comes from a fork, so the token is read-only" : void 0;
	let commented = false;
	if (inputs.comment && ctx.pr !== void 0) {
		if (readOnly !== void 0) log.annotate("notice", `Not commenting: ${readOnly}. The report is in the job summary.`, "depward");
		else if (gh === void 0) log.annotate("warning", "Not commenting: no github-token. The report is in the job summary.", "depward");
		else try {
			const r = await upsertStickyComment(gh, ctx.pr, COMMENT_MARKER, markdown, { createIfMissing: view.packages.length > 0 });
			commented = r.action !== "skipped";
			if (r.action !== "skipped") {
				outputs["comment-url"] = r.url;
				log.info(`depward: ${r.action} the PR comment ${r.url}`);
			}
		} catch (err) {
			if (!(err instanceof GitHubApiError) || err.status !== 403 && err.status !== 404) throw err;
			log.annotate("warning", `Could not comment (HTTP ${err.status}); the job needs "permissions: pull-requests: write". The report is in the job summary.`, "depward");
		}
	}
	if (!commented) await appendSummary(env, markdown);
	if (inputs.sarif) {
		if (readOnly !== void 0) log.annotate("notice", `Not uploading SARIF: ${readOnly}.`, "depward");
		else if (gh === void 0 || ctx.sha === "" || ctx.ref === "") log.annotate("warning", "Not uploading SARIF: no github-token, GITHUB_SHA, or GITHUB_REF.", "depward");
		else try {
			const id = await gh.uploadSarif({
				sarif,
				commitSha: ctx.sha,
				ref: ctx.ref,
				toolName: "depward"
			});
			log.info(`depward: uploaded SARIF${id ? ` (${id})` : ""}`);
		} catch (err) {
			if (!(err instanceof GitHubApiError) || err.status !== 403 && err.status !== 404) throw err;
			log.annotate("warning", `Could not upload SARIF (HTTP ${err.status}). Code scanning must be available for the repository, and the job needs "permissions: security-events: write".`, "depward");
		}
	}
	const failedLookups = view.packages.filter((p) => p.errors.length > 0).length;
	const reached = reachesFailOn(view.packages, inputs.failOn);
	outputs["failed"] = String(reached || failedLookups > 0);
	await setOutputs(env, outputs);
	if (reached) log.annotate("error", `Dependency risk ${view.risk} reaches fail-on ${inputs.failOn}.`, "depward");
	if (failedLookups > 0) log.annotate("error", `${failedLookups} package lookup${failedLookups === 1 ? "" : "s"} failed, so part of the change went unchecked.`, "depward");
	return reached || failedLookups > 0 ? 1 : 0;
}
/** Turns an unexpected error into a failed step with one error annotation. */
function reportError(log, err) {
	const message = isDepwardError(err) ? `${err.code}: ${err.message}` : err instanceof Error ? err.message : "unknown error";
	log.annotate("error", message, "depward");
	return 1;
}
// src/main.ts
const env = process.env;
const log = createLog((line) => process.stdout.write(`${line}\n`));
const rt = {
	version: VERSION,
	env,
	cwd: process.cwd(),
	now: () => performance.now(),
	stdout: (s) => process.stdout.write(s),
	stderr: (s) => process.stderr.write(s)
};
try {
	process.exitCode = await runAction({
		env,
		log,
		version: VERSION,
		computeView: async (base) => (await computeDiff({
			lockfile: true,
			positionals: [],
			base,
			head: void 0,
			concurrency: 8,
			config: void 0,
			offline: false
		}, rt)).view,
		github: (token) => createGitHub({
			token,
			repository: env["GITHUB_REPOSITORY"] ?? "",
			...env["GITHUB_API_URL"] ? { apiUrl: env["GITHUB_API_URL"] } : {}
		})
	});
} catch (err) {
	process.exitCode = reportError(log, err);
}
export {};
