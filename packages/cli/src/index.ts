import { parseArgs } from "node:util";

/** The version of `depward`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

/** Process exit codes. See `docs/specs/gate.md` §CLI. */
export const EXIT: { readonly allow: 0; readonly error: 1; readonly ask: 10; readonly deny: 20 } = {
  allow: 0,
  error: 1,
  ask: 10,
  deny: 20,
};

/** Output sinks, injectable for tests. */
export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

const USAGE = `Usage: depward <command> [options]

Commands are added in Phase 2 (check, hook) and Phase 3 (diff).

Options:
  -h, --help     Show this help
  -v, --version  Show the version
`;

/** Runs the CLI with `argv` (without the node and script paths) and returns the exit code. */
export function main(argv: string[], io: Io): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: { help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" } },
    });
  } catch (err) {
    io.stderr(`depward: ${(err as Error).message}\n`);
    return EXIT.error;
  }
  const { values, positionals } = parsed;
  if (values.version) {
    io.stdout(`${VERSION}\n`);
    return EXIT.allow;
  }
  const [command] = positionals;
  if (values.help || command === undefined) {
    io.stdout(USAGE);
    return EXIT.allow;
  }
  io.stderr(`depward: unknown command ${JSON.stringify(command)}\n\n${USAGE}`);
  return EXIT.error;
}
