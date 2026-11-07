// Static reading of lifecycle script strings. Nothing here runs a shell; scripts are
// treated as untrusted text and only pattern-matched.

import { posix } from "node:path";
import type { InstallScripts } from "./types.ts";

/** The scripts npm runs on `npm install <pkg>` from the registry (`prepare` is not one). */
export const INSTALL_HOOKS = ["preinstall", "install", "postinstall"] as const;

/**
 * Reads the install scripts from a parsed package.json. Like npm, a `binding.gyp` with
 * no `install`/`preinstall` script implies `install: node-gyp rebuild`.
 * See https://docs.npmjs.com/cli/v11/using-npm/scripts#npm-install
 */
export function readInstallScripts(pkg: Record<string, unknown>, hasBindingGyp: boolean): InstallScripts {
  const raw = pkg["scripts"];
  const scripts = raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const out: InstallScripts = {};
  for (const k of [...INSTALL_HOOKS, "prepare"] as const) {
    const v = scripts[k];
    if (typeof v === "string" && v.trim() !== "") out[k] = v;
  }
  if (hasBindingGyp && out.install === undefined && out.preinstall === undefined) out.install = "node-gyp rebuild";
  return out;
}

const NETWORK_PATTERNS: { re: RegExp; why: string }[] = [
  { re: /(?:^|[\s;&|(`])(?:curl|wget)(?:\.exe)?(?=$|[\s;&|)`])/i, why: "runs curl/wget" },
  { re: /(?:^|[\s;&|(`])node(?:\.exe)?\s+(?:[^\s;&|]+\s+)*?(?:-e|--eval|-p|--print)(?=$|[\s=])/i, why: "runs inline code with node -e" },
  { re: /\b(?:https?|ftp):\/\//i, why: "contains a URL" },
  { re: /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|certutil|bitsadmin)\b/i, why: "runs a Windows download tool" },
];

/** Why a script string itself looks network-capable, or `undefined`. */
export function scriptNetworkReason(script: string): string | undefined {
  return NETWORK_PATTERNS.find((p) => p.re.test(script))?.why;
}

/** Splits a script into words, dropping shell operators and surrounding quotes. Best-effort. */
function words(script: string): string[] {
  return script
    .split(/\s+|&&|\|\||[;|&()]/)
    .map((w) => w.replace(/^['"]|['"]$/g, ""))
    .filter((w) => w !== "");
}

/**
 * Package files that a script may run with node: any word ending in `.js`/`.cjs`/`.mjs`,
 * and the first non-flag argument after `node`. Returned as raw words; resolve them with
 * {@link resolveLocal}.
 */
export function scriptEntryWords(script: string): string[] {
  const ws = words(script);
  const out = new Set<string>();
  for (let i = 0; i < ws.length; i++) {
    const w = ws[i] ?? "";
    if (/\.[cm]?js$/i.test(w)) out.add(w);
    if (/^(?:.*[/\\])?node(?:\.exe)?$/i.test(w)) {
      const next = ws.slice(i + 1).find((x) => !x.startsWith("-"));
      if (next !== undefined) out.add(next);
    }
  }
  return [...out];
}

/**
 * Resolves a relative path (from `fromDir`, package-relative) to a file in `has`, trying
 * the extensions and `index` files Node would. Returns `undefined` outside the package.
 */
export function resolveLocal(fromDir: string, spec: string, has: (path: string) => boolean): string | undefined {
  const joined = posix.normalize(posix.join(fromDir, spec.replaceAll("\\", "/")));
  if (joined === ".." || joined.startsWith("../") || posix.isAbsolute(joined)) return undefined;
  const base = joined.replace(/\/$/, "");
  for (const c of [base, `${base}.js`, `${base}.cjs`, `${base}.mjs`, `${base}/index.js`, `${base}/index.cjs`, `${base}/index.mjs`]) {
    if (has(c)) return c;
  }
  return undefined;
}
