// Recognize install and exec forms for npm, pnpm, yarn, and bun. Each handler gets the
// words after the program name and says what the invocation does; it doesn't parse the
// package specs themselves (see spec.ts).

import { scanArgs, valuesOf, type ScannedArgs } from "./args.ts";
import type { Word } from "./shell.ts";
import type { InvocationKind, PackageManager } from "./types.ts";

/** A package spec word found in an invocation. */
export interface SpecWord {
  readonly word: Word;
  readonly via: "install" | "exec";
  /** True for `npm init <x>` style initializers, which map `x` to `create-x`. */
  readonly initializer?: boolean;
}

/** What a handler found in one invocation. */
export interface ManagerResult {
  readonly kind: InvocationKind;
  readonly specs: readonly SpecWord[];
  readonly global: boolean;
  readonly flags: readonly string[];
  /** Shell strings the invocation runs (`npx -c "<cmd>"`), to be parsed recursively. */
  readonly scripts: readonly Word[];
  /** Why the invocation can't be understood, if it can't. */
  readonly problem?: string;
}

type Handler = (args: readonly Word[]) => ManagerResult;

// Flags that take a value. Unknown flags are assumed to be boolean; if one isn't, its
// value is read as a package spec, which at worst produces an extra finding.
const COMMON_VALUES = ["--registry", "--loglevel", "--cpu", "--os", "--libc", "--network-concurrency"];
// prettier-ignore
const NPM_VALUES = new Set([
  ...COMMON_VALUES,
  "--prefix", "-C", "--tag", "--workspace", "-w", "--cache", "--userconfig", "--globalconfig", "--omit",
  "--include", "--install-strategy", "--save-prefix", "--before", "--otp", "--scope", "--location",
  "--auth-type", "--fetch-timeout", "--fetch-retries", "--script-shell", "--node-options", "--lockfile-version",
  "--access", "--depth",
]);
// In `npm exec` and `npx`, -p is --package and -c is --call (elsewhere they're booleans).
const NPM_EXEC_VALUES = new Set([...NPM_VALUES, "--package", "-p", "--call", "-c"]);
// prettier-ignore
const PNPM_VALUES = new Set([
  ...COMMON_VALUES,
  "--filter", "-F", "--filter-prod", "--dir", "-C", "--reporter", "--store-dir", "--virtual-store-dir",
  "--modules-dir", "--lockfile-dir", "--config-dir", "--global-dir", "--package", "--allow-build",
  "--child-concurrency", "--resolution-mode", "--node-linker", "--workspace-concurrency", "--test-pattern",
  "--changed-files-ignore-pattern",
]);
// prettier-ignore
const YARN_VALUES = new Set([
  ...COMMON_VALUES,
  "--cwd", "--network-timeout", "--modules-folder", "--mutex", "--cache-folder", "--global-folder",
  "--link-folder", "--preferred-cache-folder", "--use-yarnrc", "--package", "-p", "--mode",
]);
// prettier-ignore
const BUN_VALUES = new Set([
  ...COMMON_VALUES,
  "--cwd", "--cache-dir", "--backend", "--config", "-c", "--filter", "--concurrent-scripts", "--omit",
  "--linker", "--package", "-p",
]);

// prettier-ignore
const NPM_INSTALL = new Set([
  "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
  "add", "install-test", "it",
]);
const NPM_LOCKFILE = new Set(["ci", "clean-install", "ic", "install-clean", "isntall-clean", "install-ci-test", "cit"]);
const NPM_INIT = new Set(["init", "create", "innit"]);
const PACKAGE_FLAGS = ["--package", "-p"];

/** Subcommands that mark an unknown (computed) program as probably a package manager. */
export const PM_SUBCOMMANDS: ReadonlySet<string> = new Set([...NPM_INSTALL, ...NPM_LOCKFILE, "exec", "x", "dlx", "create", "init", "a"]);

const GLOBAL_FLAGS = new Set(["-g", "--global", "--global=true", "--location=global"]);

function result(kind: InvocationKind, flags: readonly string[], specs: readonly SpecWord[] = []): ManagerResult {
  return { kind, specs, flags, global: flags.some((f) => GLOBAL_FLAGS.has(f)), scripts: [] };
}

function problem(flags: readonly string[], why: string): ManagerResult {
  return { ...result("other", flags), problem: why };
}

/** `install <specs>`, or lockfile mode when there are none (if `bareIsLockfile`). */
function install(top: ScannedArgs, values: ReadonlySet<string>, bareIsLockfile: boolean): ManagerResult {
  const sub = scanArgs(top.rest, values, false);
  const flags = [...top.flags, ...sub.flags];
  if (sub.positionals.length === 0 && bareIsLockfile) return result("lockfile", flags);
  return result(
    "install",
    flags,
    sub.positionals.map((word) => ({ word, via: "install" })),
  );
}

/**
 * Exec forms (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`). With `--package`, the
 * listed packages are fetched and the positional is a binary name; otherwise the first
 * positional is the package. Words after it belong to the program being run.
 */
function exec(args: readonly Word[], values: ReadonlySet<string>, prior?: ScannedArgs, callFlags: readonly string[] = []): ManagerResult {
  const a = scanArgs(args, values, true);
  const flags = [...(prior?.flags ?? []), ...a.flags];
  const all = [...(prior?.values ?? []), ...a.values];
  const packages = valuesOf(all, PACKAGE_FLAGS);
  const scripts = valuesOf(all, callFlags);
  if (packages.length > 0) return result("exec", flags, packages.map((word) => ({ word, via: "exec" })));
  if (scripts.length > 0) return { ...result("exec", flags), scripts };
  const first = a.positionals[0];
  return result("exec", flags, first === undefined ? [] : [{ word: first, via: "exec" }]);
}

/** Initializers: `npm init <x>`, `<pm> create <x>`. Without `<x>`, `npm init` writes package.json. */
function initializer(top: ScannedArgs, values: ReadonlySet<string>): ManagerResult {
  const a = scanArgs(top.rest, values, true);
  const flags = [...top.flags, ...a.flags];
  const first = a.positionals[0];
  if (first === undefined) return result("other", flags);
  return result("exec", flags, [{ word: first, via: "exec", initializer: true }]);
}

/** Scan up to the subcommand. Returns a problem result if the subcommand is computed. */
function subcommand(args: readonly Word[], values: ReadonlySet<string>): [ScannedArgs, string | undefined] | ManagerResult {
  const top = scanArgs(args, values, true);
  const sub = top.positionals[0];
  if (sub?.dynamic === true) return problem(top.flags, "the subcommand is computed at run time");
  return [top, sub?.text];
}

const npm: Handler = (args) => {
  const scanned = subcommand(args, NPM_VALUES);
  if (!Array.isArray(scanned)) return scanned;
  const [top, sub] = scanned;
  if (sub === undefined) return result("other", top.flags);
  if (NPM_INSTALL.has(sub)) return install(top, NPM_VALUES, true);
  if (NPM_LOCKFILE.has(sub)) return result("lockfile", [...top.flags, ...scanArgs(top.rest, NPM_VALUES, false).flags]);
  if (sub === "exec" || sub === "x") return exec(top.rest, NPM_EXEC_VALUES, top, ["--call", "-c"]);
  if (NPM_INIT.has(sub)) return initializer(top, NPM_VALUES);
  return result("other", top.flags);
};

const npx: Handler = (args) => exec(args, NPM_EXEC_VALUES, undefined, ["--call", "-c"]);

const pnpm: Handler = (args) => {
  const scanned = subcommand(args, PNPM_VALUES);
  if (!Array.isArray(scanned)) return scanned;
  const [top, sub] = scanned;
  if (sub === "add") return install(top, PNPM_VALUES, false);
  if (sub === "install" || sub === "i") return install(top, PNPM_VALUES, true);
  if (sub === "dlx") return exec(top.rest, PNPM_VALUES, top);
  if (sub === "create") return initializer(top, PNPM_VALUES);
  return result("other", top.flags);
};

const pnpx: Handler = (args) => exec(args, PNPM_VALUES);

const yarn: Handler = (args) => {
  const scanned = subcommand(args, YARN_VALUES);
  if (!Array.isArray(scanned)) return scanned;
  const [top, sub] = scanned;
  if (sub === undefined || sub === "install") return result("lockfile", [...top.flags, ...scanArgs(top.rest, YARN_VALUES, false).flags]);
  if (sub === "add") return install(top, YARN_VALUES, false);
  if (sub === "dlx") return exec(top.rest, YARN_VALUES, top);
  if (sub === "create") return initializer(top, YARN_VALUES);
  if (sub === "global") {
    const g = subcommand(top.rest, YARN_VALUES);
    if (!Array.isArray(g)) return g;
    const [inner, verb] = g;
    if (verb !== "add") return result("other", [...top.flags, ...inner.flags]);
    const r = install({ ...inner, flags: [...top.flags, ...inner.flags] }, YARN_VALUES, false);
    return { ...r, global: true };
  }
  if (sub === "workspace") {
    // `yarn workspace <name> <command…>`: skip the workspace name.
    const ws = scanArgs(top.rest, YARN_VALUES, true);
    const r = yarn(ws.rest);
    return { ...r, flags: [...top.flags, ...ws.flags, ...r.flags] };
  }
  return result("other", top.flags);
};

const bun: Handler = (args) => {
  const scanned = subcommand(args, BUN_VALUES);
  if (!Array.isArray(scanned)) return scanned;
  const [top, sub] = scanned;
  if (sub === "add" || sub === "a") return install(top, BUN_VALUES, false);
  if (sub === "install" || sub === "i") return install(top, BUN_VALUES, true);
  if (sub === "x") return exec(top.rest, BUN_VALUES, top);
  if (sub === "create" || sub === "c") return initializer(top, BUN_VALUES);
  return result("other", top.flags);
};

const bunx: Handler = (args) => exec(args, BUN_VALUES);

/** Handlers by program name, with the manager each belongs to. */
export const MANAGERS: ReadonlyMap<string, readonly [PackageManager, Handler]> = new Map([
  ["npm", ["npm", npm]],
  ["npx", ["npm", npx]],
  ["pnpm", ["pnpm", pnpm]],
  ["pnpx", ["pnpm", pnpx]],
  ["yarn", ["yarn", yarn]],
  ["yarnpkg", ["yarn", yarn]],
  ["bun", ["bun", bun]],
  ["bunx", ["bun", bunx]],
]);
