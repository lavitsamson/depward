// `depward caps`: the capability lockfile. Spec: docs/specs/caps.md § Static layer.
// Argument parsing uses node:util parseArgs (https://nodejs.org/api/util.html#utilparseargsconfig).

import { readFile, rename, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { parseArgs } from "node:util";
import {
  CAPS_LOCKFILE_NAME,
  DEFAULT_SCAN_CONCURRENCY,
  parseCapsLockfile,
  scanCapabilities,
  serializeCapsLockfile,
  type CapsLockfile,
  type ScanResult,
} from "@depward/caps";
import { escapeUnsafe } from "@depward/core";
import { openContext } from "./context.ts";
import { EXIT, UsageError, type Runtime } from "./runtime.ts";

export const CAPS_USAGE: string = `Usage: depward caps scan [options]

Writes ${CAPS_LOCKFILE_NAME}: the capabilities (fs, net, child_process, env, ...)
that static analysis finds in every registry package of the lockfiles in the current
directory. Package code is never run. Entries with capabilities are approved as
"static"; a re-scan keeps the approvals of entries whose capabilities are unchanged
and drops entries that are no longer locked. Nothing is written if any package can't
be analyzed.

Options:
      --output <path>     Where to write (default ${CAPS_LOCKFILE_NAME}); "-" for stdout
      --json              Print the scan summary as JSON
      --concurrency <n>   Packages analyzed at once (default ${DEFAULT_SCAN_CONCURRENCY})
      --config <path>     Config file (for the registry URL)
      --offline           Use only cached registry data (also: DEPWARD_OFFLINE=1)
  -h, --help              Show this help

Exit codes: 0 written, 1 error (nothing written).
`;

interface ScanArgs {
  readonly output: string;
  readonly json: boolean;
  readonly concurrency: number;
  readonly config: string | undefined;
  readonly offline: boolean;
  readonly help: boolean;
}

function parse(argv: string[]): ScanArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      output: { type: "string" },
      json: { type: "boolean" },
      concurrency: { type: "string" },
      config: { type: "string" },
      offline: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  const help = values.help ?? false;
  if (!help) {
    const [sub, ...extra] = positionals;
    if (sub === undefined) throw new UsageError("give a subcommand: scan");
    if (sub !== "scan") throw new UsageError(`unknown caps subcommand ${JSON.stringify(escapeUnsafe(sub, 50))}`);
    if (extra.length > 0) throw new UsageError("caps scan takes no package arguments");
  }
  let concurrency = DEFAULT_SCAN_CONCURRENCY;
  if (values.concurrency !== undefined) {
    concurrency = Number(values.concurrency);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) throw new UsageError("--concurrency must be an integer from 1 to 64");
  }
  const output = values.output ?? CAPS_LOCKFILE_NAME;
  if (output === "") throw new UsageError("--output needs a path");
  if (output === "-" && values.json) throw new UsageError('--json conflicts with --output -');
  return { output, json: values.json ?? false, concurrency, config: values.config, offline: values.offline ?? false, help };
}

/** The current capability lockfile at `path`, or `null` when there is none. */
async function readExisting(path: string): Promise<CapsLockfile | null> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  return parseCapsLockfile(text, basename(path));
}

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

function summaryText(r: ScanResult, written: string): string {
  const lines = [
    `Scanned ${plural(r.counts.scanned, "package")} from ${r.lockfiles.join(", ")}: ${r.counts.withCapabilities} with capabilities.`,
  ];
  if (r.counts.kept > 0 || r.counts.dropped > 0) lines.push(`Kept ${plural(r.counts.kept, "approval")}; dropped ${plural(r.counts.dropped, "entry", "entries")} no longer locked.`);
  if (r.skipped.length > 0) {
    const sources = [...new Set(r.skipped.map((s) => s.source))].toSorted().join(", ");
    lines.push(`Skipped ${plural(r.skipped.length, "non-registry entry", "non-registry entries")} (${sources}).`);
  }
  lines.push(`Wrote ${written}.`);
  return `${lines.join("\n")}\n`;
}

/** Writes through a temporary file, so an interrupted write never leaves half a lockfile. */
async function writeAtomic(path: string, text: string): Promise<void> {
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, text);
  await rename(tmp, path);
}

/** Runs `depward caps` and returns the exit code. */
export async function runCaps(argv: string[], rt: Runtime): Promise<number> {
  const args = parse(argv);
  if (args.help) {
    rt.stdout(CAPS_USAGE);
    return EXIT.allow;
  }
  const toStdout = args.output === "-";
  const path = toStdout ? null : resolve(rt.cwd, args.output);
  const existing = path === null ? null : await readExisting(path);
  const { registry, analysisCache, overrides } = await openContext(rt, args);
  const result = await scanCapabilities({
    cwd: rt.cwd,
    registry,
    existing,
    concurrency: args.concurrency,
    ...(analysisCache === undefined ? {} : { analysisCache }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
    ...(overrides.tarLimits === undefined ? {} : { tarLimits: overrides.tarLimits }),
    ...(overrides.analyze === undefined ? {} : { analyze: overrides.analyze }),
  });

  if (result.errors.length > 0) {
    for (const e of result.errors) rt.stderr(`depward: ${e.code}: ${escapeUnsafe(e.message, 500)}\n`);
    rt.stderr(`depward: ${plural(result.errors.length, "package")} could not be analyzed; nothing was written\n`);
    if (result.errors.some((e) => e.code === "TIMEOUT" || e.code === "NETWORK")) {
      rt.stderr("depward: network failures are often transient. Analyzed packages are cached, so running the scan again continues where this one stopped; a lower --concurrency helps with large tarballs\n");
    }
    return EXIT.error;
  }

  const text = serializeCapsLockfile(result.lockfile);
  if (path === null) rt.stdout(text);
  else await writeAtomic(path, text);
  const written = path === null ? "stdout" : escapeUnsafe(args.output, 200);
  if (args.json) {
    rt.stdout(`${JSON.stringify({ output: path === null ? "-" : args.output, lockfiles: result.lockfiles, counts: result.counts, skipped: result.skipped }, null, 2)}\n`);
  } else {
    (toStdout ? rt.stderr : rt.stdout)(summaryText(result, written));
  }
  return EXIT.allow;
}
