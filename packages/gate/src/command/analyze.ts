// Turn a shell command line into package requests. Walks each simple command, skips
// prefixes (`VAR=x`, `env`, `sudo`, reserved words), descends into strings that are run
// as shell code (`sh -c`, `eval`, `cmd /c`, `powershell -Command`, heredocs fed to a
// shell), and hands package-manager invocations to the handlers in managers.ts.

import { Buffer } from "node:buffer";
import { findingDocsUrl, type Finding } from "@depward/core";
import { programName } from "./args.ts";
import { MANAGERS, PM_SUBCOMMANDS, type ManagerResult, type SpecWord } from "./managers.ts";
import { MAX_SHELL_DEPTH, parseShell, type SimpleCommand, type Word } from "./shell.ts";
import { createPackageSpec, parsePackageSpec, type NonRegistrySpec } from "./spec.ts";
import type { CommandAnalysis, Invocation, PackageManager, PackageRequest } from "./types.ts";

const MENTIONS_MANAGER = /(?:^|[^\w-])(?:npm|npx|pnpm|pnpx|yarn|yarnpkg|bun|bunx|corepack)(?![\w-])/i;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const RESERVED = new Set(["!", "{", "}", "if", "then", "else", "elif", "do", "while", "until"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"]);
const MAX_SNIPPET = 200;

interface Wrapper {
  /** Flags that take a value. */
  readonly values?: readonly string[];
  /** Positional arguments before the wrapped command (`timeout <duration> cmd`). */
  readonly positionals?: number;
}

// Commands that run another command given as their remaining arguments.
const WRAPPERS: ReadonlyMap<string, Wrapper> = new Map<string, Wrapper>([
  ["env", { values: ["-u", "--unset", "-C", "--chdir"] }],
  ["sudo", { values: ["-u", "--user", "-g", "--group", "-C", "-D", "--chdir", "-h", "--host", "-p", "--prompt", "-r", "-t", "-U", "-T"] }],
  ["doas", { values: ["-u", "-C"] }],
  ["command", {}],
  ["builtin", {}],
  ["exec", { values: ["-a"] }],
  ["nohup", {}],
  ["time", { values: ["-f", "--format", "-o", "--output"] }],
  ["nice", { values: ["-n", "--adjustment"] }],
  ["ionice", { values: ["-c", "-n", "-p"] }],
  ["stdbuf", { values: ["-i", "-o", "-e"] }],
  ["timeout", { values: ["-s", "--signal", "-k", "--kill-after"], positionals: 1 }],
  ["cross-env", {}],
  ["dotenv", { values: ["-e", "-c", "-v", "-p"] }],
  ["xargs", { values: ["-n", "-I", "-L", "-P", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file"] }],
]);

const SOURCE_NAMES: Record<NonRegistrySpec["source"], string> = {
  git: "a git repository",
  url: "a URL",
  file: "a local path",
  workspace: "the workspace",
  other: "a non-npm source",
};

function truncate(text: string): string {
  return text.length > MAX_SNIPPET ? `${text.slice(0, MAX_SNIPPET)}…` : text;
}

class Analysis {
  readonly requests: PackageRequest[] = [];
  readonly findings: Finding[] = [];
  readonly invocations: Invocation[] = [];

  unparseable(snippet: string, detail: string): void {
    this.findings.push({
      id: "unparseable-command",
      severity: "medium",
      package: "(command)",
      message: "depward can't tell what this package-manager command installs",
      evidence: [{ snippet: truncate(snippet), detail }],
      docsUrl: findingDocsUrl("unparseable-command"),
    });
  }

  /** Parse and analyze shell source. */
  text(source: string, depth: number): void {
    if (depth > MAX_SHELL_DEPTH) {
      if (MENTIONS_MANAGER.test(source)) this.unparseable(source, "command nesting is too deep");
      return;
    }
    const parsed = parseShell(source, depth);
    if (parsed.error !== undefined) {
      // The shell runs nothing from a line it can't parse, so report only the error.
      if (MENTIONS_MANAGER.test(source)) this.unparseable(source, parsed.error);
      return;
    }
    for (const command of parsed.commands) this.command(command, depth);
  }

  /** Analyze a string that will run as shell code, unless it's computed at run time. */
  script(word: Word | undefined, snippet: string, depth: number): void {
    if (word === undefined) return;
    if (word.dynamic) {
      if (MENTIONS_MANAGER.test(word.text)) this.unparseable(snippet, "a shell script is computed at run time");
      return;
    }
    this.text(word.text, depth + 1);
  }

  /** Join words into one script (`eval a b`, `cmd /c a b`). */
  joined(words: readonly Word[], snippet: string, depth: number): void {
    if (words.length === 0) return;
    this.script({ text: words.map((w) => w.text).join(" "), dynamic: words.some((w) => w.dynamic) }, snippet, depth);
  }

  command(cmd: SimpleCommand, depth: number): void {
    const words = cmd.words;
    let i = 0;
    let xargs = false;
    for (;;) {
      const word = words[i];
      if (word === undefined) return;
      if (word.dynamic) {
        const next = words[i + 1];
        if (next !== undefined && PM_SUBCOMMANDS.has(next.text)) this.unparseable(cmd.text, "the program name is computed at run time");
        return;
      }
      if (RESERVED.has(word.text) || ASSIGNMENT.test(word.text)) {
        i++;
        continue;
      }
      const prog = programName(word.text);
      const wrapper = WRAPPERS.get(prog);
      if (wrapper === undefined) break;
      if (prog === "env") {
        const split = this.envSplitString(words, i + 1);
        if (split !== undefined) return this.joined(split, cmd.text, depth);
      }
      if (prog === "xargs") xargs = true;
      i = skipWrapper(words, i + 1, wrapper);
    }

    const prog = programName((words[i] as Word).text);
    const args = words.slice(i + 1);
    if (SHELLS.has(prog)) return this.shell(args, cmd, depth);
    if (prog === "eval") return this.joined(args, cmd.text, depth);
    if (prog === "cmd") {
      const c = args.findIndex((w) => /^\/[ck]$/i.test(w.text));
      return c < 0 ? undefined : this.joined(args.slice(c + 1), cmd.text, depth);
    }
    if (prog === "powershell" || prog === "pwsh") return this.powershell(args, cmd.text, depth);

    let managerWords = words.slice(i);
    if (prog === "corepack") {
      managerWords = args;
      const first = args[0];
      if (first === undefined || first.dynamic) return;
      managerWords = [{ text: first.text.replace(/@.*$/, ""), dynamic: false }, ...args.slice(1)];
    }
    const entry = MANAGERS.get(programName((managerWords[0] as Word).text));
    if (entry === undefined) return;
    const [manager, handler] = entry;
    const r = handler(managerWords.slice(1));
    this.invocations.push({ manager, kind: r.kind, argv: managerWords.map((w) => w.text) });
    this.manager(manager, r, cmd, depth, xargs);
  }

  /** `env -S "<string>"` splits the string into words; returns them plus the rest. */
  private envSplitString(words: readonly Word[], start: number): Word[] | undefined {
    for (let j = start; j < words.length; j++) {
      const t = (words[j] as Word).text;
      if (t === "-S" || t === "--split-string") return words.slice(j + 1);
      if (t.startsWith("--split-string=")) return [{ text: t.slice(15), dynamic: (words[j] as Word).dynamic }, ...words.slice(j + 1)];
      if (!t.startsWith("-")) return undefined;
    }
    return undefined;
  }

  private shell(args: readonly Word[], cmd: SimpleCommand, depth: number): void {
    let sawC = false;
    for (let j = 0; j < args.length; j++) {
      const t = (args[j] as Word).text;
      if (t === "--" || t === "-") return sawC ? this.script(args[j + 1], cmd.text, depth) : undefined;
      if (/^[-+]O?o$/.test(t) || t === "--rcfile" || t === "--init-file") {
        j++;
        continue;
      }
      if (/^[-+][A-Za-z]+$/.test(t)) {
        if (t.startsWith("-") && t.includes("c")) sawC = true;
        continue;
      }
      if (t.startsWith("--")) continue;
      // First operand: the script string with -c, otherwise a script file we can't see.
      return sawC ? this.script(args[j], cmd.text, depth) : undefined;
    }
    if (!sawC) for (const input of cmd.stdin) this.text(input, depth + 1);
  }

  private powershell(args: readonly Word[], snippet: string, depth: number): void {
    const VALUES = ["-executionpolicy", "-ep", "-ex", "-windowstyle", "-w", "-configurationname", "-inputformat", "-outputformat", "-workingdirectory", "-wd", "-settingsfile"];
    for (let j = 0; j < args.length; j++) {
      const t = (args[j] as Word).text.toLowerCase();
      if (t === "-command" || t === "-c") return this.joined(args.slice(j + 1), snippet, depth);
      if (t === "-encodedcommand" || t === "-enc" || t === "-e" || t === "-ec") {
        const encoded = args[j + 1];
        if (encoded === undefined) return;
        if (encoded.dynamic) return this.unparseable(snippet, "an encoded command is computed at run time");
        return this.text(Buffer.from(encoded.text, "base64").toString("utf16le"), depth + 1);
      }
      if (t === "-file" || t === "-f") return;
      if (VALUES.includes(t)) j++;
      else if (!t.startsWith("-")) return this.joined(args.slice(j), snippet, depth);
    }
  }

  private manager(manager: PackageManager, r: ManagerResult, cmd: SimpleCommand, depth: number, xargs: boolean): void {
    if (r.problem !== undefined) this.unparseable(cmd.text, r.problem);
    if (xargs && r.kind !== "other") this.unparseable(cmd.text, "package specs come from xargs input");
    for (const script of r.scripts) this.script(script, cmd.text, depth);
    for (const spec of r.specs) this.spec(manager, r, spec, cmd);
  }

  private spec(manager: PackageManager, r: ManagerResult, { word, via, initializer }: SpecWord, cmd: SimpleCommand): void {
    if (word.dynamic) return this.unparseable(cmd.text, "a package spec is computed at run time");
    const raw = initializer === true ? createPackageSpec(word.text) : word.text;
    const spec = parsePackageSpec(raw);
    if (spec.source === "invalid") return this.unparseable(cmd.text, `${JSON.stringify(raw)}: ${spec.reason}`);
    const name = spec.source === "registry" ? spec.name : (spec.alias ?? raw);
    const range = spec.source === "registry" ? spec.range : raw;
    const request: PackageRequest = {
      raw,
      source: spec.source,
      name,
      range,
      ...(spec.alias === undefined ? {} : { alias: spec.alias }),
      via,
      manager,
      global: r.global,
      flags: r.flags,
      command: cmd.text,
    };
    this.requests.push(request);
    if (spec.source !== "registry" && spec.source !== "workspace") {
      this.findings.push({
        id: "non-registry-source",
        severity: "medium",
        package: name,
        message: `${raw} is installed from ${SOURCE_NAMES[spec.source]}, not the npm registry, so depward can't check it`,
        evidence: [{ snippet: truncate(cmd.text) }],
        docsUrl: findingDocsUrl("non-registry-source"),
      });
    }
    if (r.global) {
      this.findings.push({
        id: "global-install",
        severity: "info",
        package: name,
        message: `${spec.source === "registry" ? `${name}@${range}` : raw} is installed globally`,
        evidence: [{ snippet: truncate(cmd.text) }],
        docsUrl: findingDocsUrl("global-install"),
      });
    }
  }
}

function skipWrapper(words: readonly Word[], start: number, wrapper: Wrapper): number {
  let i = start;
  while (i < words.length) {
    const t = (words[i] as Word).text;
    if (t === "--") return i + 1;
    if (ASSIGNMENT.test(t)) i++;
    else if (t.length > 1 && t.startsWith("-")) i += wrapper.values?.includes(t) === true ? 2 : 1;
    else break;
  }
  return i + (wrapper.positionals ?? 0);
}

/**
 * Find every package a shell command line would install or run, without executing it.
 *
 * Recognizes npm, pnpm, yarn, and bun install and exec forms (including `npx`, `dlx`,
 * `bunx`, and `create`/`init` initializers), across chained commands, subshells,
 * substitutions, `sh -c` strings, and common prefixes like `env` and `sudo`.
 * Lockfile installs (`npm ci`, bare `pnpm install`) produce no requests.
 *
 * @example
 * parseInstallCommand("cd app && npm i -D zod@3").requests[0];
 * // { raw: "zod@3", source: "registry", name: "zod", range: "3", via: "install", manager: "npm", … }
 */
export function parseInstallCommand(command: string): CommandAnalysis {
  const analysis = new Analysis();
  analysis.text(command, 0);
  return { requests: analysis.requests, findings: analysis.findings, invocations: analysis.invocations };
}
