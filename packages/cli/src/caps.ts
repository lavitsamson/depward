// `depward caps`: the capability lockfile. Spec: docs/specs/caps.md § Static layer.
// Argument parsing uses node:util parseArgs (https://nodejs.org/api/util.html#utilparseargsconfig).
// `scan` lives here with the shared helpers; `check` and `approve` have their own files.

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { CAPS_LOCKFILE_NAME, DEFAULT_SCAN_CONCURRENCY, scanCapabilities, serializeCapsLockfile, type ScanResult } from "@depward/caps";
import { escapeUnsafe } from "@depward/core";
import { runCapsApprove } from "./caps-approve.ts";
import { runCapsCheck } from "./caps-check.ts";
import { runCapsCompare } from "./caps-compare.ts";
import { COMMON_OPTIONS, parseCapsFile, parseConcurrency, plural, readCapsFile, retryHint, writeAtomic } from "./caps-shared.ts";
import { openContext } from "./context.ts";
import { EXIT, UsageError, type Runtime } from "./runtime.ts";

export const CAPS_USAGE: string = `Usage: depward caps scan [options]
       depward caps check [options]
       depward caps approve <name>[@version]... [options]
       depward caps compare [options]

scan     Writes ${CAPS_LOCKFILE_NAME}: the capabilities (fs, net, child_process,
         env, ...) that static analysis finds in every registry package of the
         lockfiles in the current directory. Entries with capabilities are approved
         as "static". A re-scan keeps the approvals of unchanged entries and drops
         entries that are no longer locked. Nothing is written if a package can't be
         analyzed.
check    Fails (exit 20) when a locked version uses a capability that its entry in
         ${CAPS_LOCKFILE_NAME} doesn't list. Without an exact name@version entry,
         the package's highest approved version is the reference. For CI.
approve  Approves the capabilities of the locked versions of a package (or of one
         version) and records who, when, and why.
compare  Compares what "node --import @depward/caps/register" observed at runtime
         (.depward/caps-observed.json) with ${CAPS_LOCKFILE_NAME}. Same report and exit
         codes as check. Runtime observation is defense in depth, not a sandbox.

Package code is never run.

Options (all):
      --caps-file <path>  The capability lockfile (default ${CAPS_LOCKFILE_NAME})
      --concurrency <n>   Packages analyzed at once (default ${DEFAULT_SCAN_CONCURRENCY})
      --config <path>     Config file (default: depward.config.json, or the
                          "depward" key of package.json)
      --offline           Use only cached registry data (also: DEPWARD_OFFLINE=1)
  -h, --help              Show this help

scan:
      --output <path>     Where to write (default: --caps-file); "-" for stdout
      --json              Print the scan summary as JSON

check, compare:
      --format <fmt>      terminal (default), json, markdown, sarif
      --json              Same as --format json
      --fail-on <level>   Also exit 20 when a package's risk reaches this level:
                          critical (default), high, medium, low, info, or none
      --verbose           Also show findings the config allows

compare:
      --observed <path>   The observed file (default .depward/caps-observed.json)

approve:
      --cap <cap>         Approve only this capability (repeatable); others stay
                          unapproved
      --reason <text>     Why the capabilities are acceptable
      --by <name>         Who approves (default: git config user.name, else "manual")

Exit codes: scan, approve: 0 written, 1 error (nothing written).
check, compare: 0 pass, 20 unapproved capability or --fail-on reached, 1 a package
could not be checked.
`;

/** The caps subcommands. */
const SUBCOMMANDS: Record<string, (argv: string[], rt: Runtime) => Promise<number>> = {
  scan: runCapsScan,
  check: runCapsCheck,
  approve: runCapsApprove,
  compare: runCapsCompare,
};

/** Runs `depward caps` and returns the exit code. */
export async function runCaps(argv: string[], rt: Runtime): Promise<number> {
  // --help anywhere prints the one caps usage (subcommands don't have their own).
  if (argv.includes("--help") || argv.includes("-h")) {
    rt.stdout(CAPS_USAGE);
    return EXIT.allow;
  }
  const [sub, ...rest] = argv;
  if (sub === undefined) throw new UsageError("give a subcommand: scan, check, approve, or compare");
  const run = Object.hasOwn(SUBCOMMANDS, sub) ? SUBCOMMANDS[sub] : undefined;
  if (run === undefined) throw new UsageError(`unknown caps subcommand ${JSON.stringify(escapeUnsafe(sub, 50))}`);
  return run(rest, rt);
}

// ---------------------------------------------------------------------------------------
// scan

function summaryText(r: ScanResult, written: string): string {
  const lines = [`Scanned ${plural(r.counts.scanned, "package")} from ${r.lockfiles.join(", ")}: ${r.counts.withCapabilities} with capabilities.`];
  if (r.counts.kept > 0 || r.counts.dropped > 0) lines.push(`Kept ${plural(r.counts.kept, "approval")}; dropped ${plural(r.counts.dropped, "entry", "entries")} no longer locked.`);
  if (r.skipped.length > 0) {
    const sources = [...new Set(r.skipped.map((s) => s.source))].toSorted().join(", ");
    lines.push(`Skipped ${plural(r.skipped.length, "non-registry entry", "non-registry entries")} (${sources}).`);
  }
  lines.push(`Wrote ${written}.`);
  return `${lines.join("\n")}\n`;
}

async function runCapsScan(argv: string[], rt: Runtime): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: { ...COMMON_OPTIONS, output: { type: "string" }, json: { type: "boolean" } },
  });
  if (positionals.length > 0) throw new UsageError("caps scan takes no package arguments");
  const concurrency = parseConcurrency(values.concurrency);
  const output = values.output ?? parseCapsFile(values["caps-file"]);
  if (output === "") throw new UsageError("--output needs a path");
  if (output === "-" && values.json) throw new UsageError("--json conflicts with --output -");

  const path = output === "-" ? null : resolve(rt.cwd, output);
  const existing = path === null ? null : await readCapsFile(path);
  const { registry, analysisCache, overrides } = await openContext(rt, { config: values.config, offline: values.offline ?? false });
  const result = await scanCapabilities({
    cwd: rt.cwd,
    registry,
    existing,
    concurrency,
    ...(analysisCache === undefined ? {} : { analysisCache }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
    ...(overrides.tarLimits === undefined ? {} : { tarLimits: overrides.tarLimits }),
    ...(overrides.analyze === undefined ? {} : { analyze: overrides.analyze }),
  });

  if (result.errors.length > 0) {
    for (const e of result.errors) rt.stderr(`depward: ${e.code}: ${escapeUnsafe(e.message, 500)}\n`);
    rt.stderr(`depward: ${plural(result.errors.length, "package")} could not be analyzed; nothing was written\n`);
    rt.stderr(retryHint(result.errors.map((e) => e.code)));
    return EXIT.error;
  }

  const text = serializeCapsLockfile(result.lockfile);
  if (path === null) rt.stdout(text);
  else await writeAtomic(path, text);
  if (values.json) {
    rt.stdout(`${JSON.stringify({ output, lockfiles: result.lockfiles, counts: result.counts, skipped: result.skipped }, null, 2)}\n`);
  } else {
    (path === null ? rt.stderr : rt.stdout)(summaryText(result, path === null ? "stdout" : escapeUnsafe(output, 200)));
  }
  return EXIT.allow;
}
