// The depward CLI. A thin wrapper over @depward/gate, @depward/diff, @depward/caps, and
// @depward/core.
// Spec: docs/specs/gate.md §CLI.

import { parseArgs } from "node:util";
import { escapeUnsafe, isDepwardError } from "@depward/core";
import { CAPS_USAGE, runCaps } from "./caps.ts";
import { CHECK_USAGE, runCheck } from "./check.ts";
import { DIFF_USAGE, runDiff } from "./diff.ts";
import { HOOK_USAGE, runHook } from "./hook.ts";
import { EXIT, UsageError, type Io, type Runtime } from "./runtime.ts";

export { EXIT, type Io } from "./runtime.ts";

/** The version of `depward`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

const USAGE = `Usage: depward <command> [options]

Commands:
  check <spec...>             Check packages before installing them
  check --command "<cmd>"     Check what a shell command would install
  diff <name> <from> <to>     Diff what two versions of a package can do
  diff --lockfile             Diff the dependency changes in the lockfiles
  hook claude                 Claude Code PreToolUse hook (hook input on stdin)
  caps scan                   Write capabilities.lock.json from the lockfiles

Run "depward <command> --help" for a command's options.

Options:
  -h, --help     Show this help
  -v, --version  Show the version

Exit codes (check, hook): 0 allow, 10 ask, 20 deny, 1 error.
`;

const COMMANDS: Record<string, { run: (argv: string[], rt: Runtime) => Promise<number>; usage: string }> = {
  caps: { run: runCaps, usage: CAPS_USAGE },
  check: { run: runCheck, usage: CHECK_USAGE },
  diff: { run: runDiff, usage: DIFF_USAGE },
  hook: { run: runHook, usage: HOOK_USAGE },
};

function errorText(err: unknown): string {
  if (isDepwardError(err)) return `${err.code}: ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

/**
 * Runs the CLI with `argv` (without the node and script paths) and resolves to the exit
 * code. Never rejects: failures print to stderr and resolve to {@link EXIT.error}.
 */
export async function main(argv: string[], io: Io): Promise<number> {
  const rt: Runtime = {
    ...io,
    version: VERSION,
    env: io.env ?? process.env,
    cwd: io.cwd ?? process.cwd(),
    now: io.now ?? (() => performance.now()),
    ...(io.isTTY === undefined ? { isTTY: process.stdout.isTTY } : {}),
  };
  const [first, ...rest] = argv;
  const command = first !== undefined && Object.hasOwn(COMMANDS, first) ? COMMANDS[first] : undefined;
  try {
    if (command) return await command.run(rest, rt);

    const { values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: { help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" } },
    });
    if (values.version) {
      rt.stdout(`${VERSION}\n`);
      return EXIT.allow;
    }
    if (values.help || positionals.length === 0) {
      rt.stdout(USAGE);
      return EXIT.allow;
    }
    throw new UsageError(`unknown command ${JSON.stringify(positionals[0])}`);
  } catch (err) {
    const usage = command?.usage ?? USAGE;
    const usageError = err instanceof UsageError || (err as { code?: unknown }).code?.toString().startsWith("ERR_PARSE_ARGS") === true;
    rt.stderr(`depward: ${escapeUnsafe(errorText(err), 500)}\n${usageError ? `\n${usage}` : ""}`);
    return EXIT.error;
  }
}
