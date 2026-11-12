// `depward diff`: the behavioral diff of one package update, or of every update in a
// lockfile change. Spec: docs/specs/diff.md §CLI. Argument parsing uses node:util
// parseArgs (https://nodejs.org/api/util.html#utilparseargsconfig).

import { parseArgs } from "node:util";
import { REPORT_FORMATS, colorEnabled, sortFindings, type ReportFormat } from "@depward/core";
import {
  DEFAULT_CONCURRENCY,
  FAIL_ON_LEVELS,
  applyPolicy,
  diffLockfile,
  diffVersions,
  reachesFailOn,
  type FailOn,
} from "@depward/diff";
import { createPolicy } from "@depward/gate";
import { openContext } from "./context.ts";
import { renderDiffMarkdown } from "./diff-markdown.ts";
import { renderDiffSarif, renderDiffTerminal, serializeDiff, type DiffView } from "./diff-render.ts";
import { EXIT, UsageError, type Runtime } from "./runtime.ts";

export const DIFF_USAGE: string = `Usage: depward diff [options] <name> <fromVersion> <toVersion>
       depward diff --lockfile [--base <ref>] [options]

Compares what one version of a package can do with what another can do: new install
scripts, capabilities, network use, secrets, endpoints, obfuscation, dependencies,
publisher, and provenance. Package code is never run.

With --lockfile, every known lockfile in the current directory is compared with the
same file at the merge-base of HEAD and --base. Updated packages are diffed; new
packages get the same registry and tarball checks as "depward check".

Options:
      --lockfile          Diff the lockfile changes instead of one package
      --base <ref>        Git ref to compare with (default origin/HEAD)
      --head <ref>        Read the lockfiles at this ref instead of the working tree
      --format <fmt>      terminal (default), json, markdown, sarif
      --json              Same as --format json
      --fail-on <level>   Exit 20 when a package's risk reaches this level:
                          critical (default), high, medium, low, info, or none
      --concurrency <n>   Packages checked at once (default ${DEFAULT_CONCURRENCY})
      --config <path>     Config file (default: depward.config.json, or the
                          "depward" key of package.json, in the current directory)
      --offline           Use only cached registry data (also: DEPWARD_OFFLINE=1)
      --verbose           Also show packages without findings, and timing
  -h, --help              Show this help

The config's "policy" overrides set to "allow" and its "allow" list keep findings
visible but out of the risk; a package on its "deny" list is critical.

Exit codes: 0 below --fail-on, 20 risk reached --fail-on, 1 error (including a
lookup that failed, so a package went unchecked; the report is still printed).
A reached --fail-on wins over a failed lookup.
`;

interface DiffArgs {
  readonly lockfile: boolean;
  readonly positionals: string[];
  readonly base: string | undefined;
  readonly head: string | undefined;
  readonly format: ReportFormat;
  readonly concurrency: number;
  readonly failOn: FailOn;
  readonly config: string | undefined;
  readonly offline: boolean;
  readonly verbose: boolean;
  readonly help: boolean;
}

function parse(argv: string[]): DiffArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      lockfile: { type: "boolean" },
      base: { type: "string" },
      head: { type: "string" },
      format: { type: "string" },
      json: { type: "boolean" },
      concurrency: { type: "string" },
      "fail-on": { type: "string" },
      config: { type: "string" },
      offline: { type: "boolean" },
      verbose: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  let format: ReportFormat = "terminal";
  if (values.format !== undefined) {
    if (!(REPORT_FORMATS as readonly string[]).includes(values.format)) throw new UsageError(`--format must be one of ${REPORT_FORMATS.join(", ")}`);
    format = values.format as ReportFormat;
  }
  if (values.json) {
    if (values.format !== undefined && values.format !== "json") throw new UsageError("--json conflicts with --format " + values.format);
    format = "json";
  }
  let concurrency = DEFAULT_CONCURRENCY;
  if (values.concurrency !== undefined) {
    concurrency = Number(values.concurrency);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) throw new UsageError("--concurrency must be an integer from 1 to 64");
  }
  const failOn = values["fail-on"] ?? "critical";
  if (!(FAIL_ON_LEVELS as readonly string[]).includes(failOn)) throw new UsageError(`--fail-on must be one of ${FAIL_ON_LEVELS.join(", ")}`);
  const args: DiffArgs = {
    lockfile: values.lockfile ?? false,
    positionals,
    base: values.base,
    head: values.head,
    format,
    concurrency,
    failOn: failOn as FailOn,
    config: values.config,
    offline: values.offline ?? false,
    verbose: values.verbose ?? false,
    help: values.help ?? false,
  };
  if (args.help) return args;
  if (args.lockfile) {
    if (positionals.length > 0) throw new UsageError("--lockfile takes no package arguments");
  } else {
    if (args.base !== undefined || args.head !== undefined) throw new UsageError("--base and --head need --lockfile");
    if (positionals.length !== 3) throw new UsageError("give <name> <fromVersion> <toVersion>, or --lockfile");
  }
  return args;
}

function render(view: DiffView, args: DiffArgs, rt: Runtime): string {
  const tool = { name: "depward", version: rt.version };
  switch (args.format) {
    case "json":
      return `${JSON.stringify(serializeDiff(view, tool, { failOn: args.failOn, failed: reachesFailOn(view.packages, args.failOn) }), null, 2)}\n`;
    case "markdown":
      return renderDiffMarkdown(view);
    case "sarif":
      return renderDiffSarif(view, tool);
    case "terminal":
      return renderDiffTerminal(view, { color: colorEnabled(rt.env, rt.isTTY), verbose: args.verbose });
  }
}

/** What {@link computeDiff} needs: a lockfile change, or one package's two versions. */
export type DiffRequest = Pick<DiffArgs, "lockfile" | "positionals" | "base" | "head" | "concurrency" | "config" | "offline">;

/**
 * Runs the diff (lockfile mode, or one package from `positionals`) with the project
 * config applied, and returns the view every renderer takes. Shared by `depward diff`
 * and the GitHub Action (action/).
 */
export async function computeDiff(args: DiffRequest, rt: Runtime): Promise<{ view: DiffView; configSource: string | null }> {
  const { config, registry, analysisCache, overrides } = await openContext(rt, args);
  const policy = createPolicy(config);
  const opts = {
    registry,
    policy,
    ...(analysisCache === undefined ? {} : { analysisCache }),
    ...(overrides.data === undefined ? {} : { data: overrides.data }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
  };

  let view: DiffView;
  if (args.lockfile) {
    const report = await diffLockfile({
      ...opts,
      cwd: rt.cwd,
      concurrency: args.concurrency,
      ...(args.base === undefined ? {} : { base: args.base }),
      ...(args.head === undefined ? {} : { head: args.head }),
    });
    view = { ...report };
  } else {
    const [name, from, to] = args.positionals as [string, string, string];
    const result = applyPolicy(await diffVersions(name, from, to, opts), policy);
    view = { packages: [result], findings: sortFindings(result.findings), risk: result.risk, lockfiles: [], skipped: [], base: null, head: null };
  }
  return { view, configSource: config.source };
}

/** Whether a diff fails: 20 when a risk reaches `failOn`, 1 when a lookup failed, else 0. */
export function diffExitCode(view: DiffView, failOn: FailOn): number {
  if (reachesFailOn(view.packages, failOn)) return EXIT.deny;
  // A failed lookup means part of the change went unchecked.
  return view.packages.some((p) => p.errors.length > 0) ? EXIT.error : EXIT.allow;
}

/** Runs `depward diff` and returns the exit code. */
export async function runDiff(argv: string[], rt: Runtime): Promise<number> {
  const args = parse(argv);
  if (args.help) {
    rt.stdout(DIFF_USAGE);
    return EXIT.allow;
  }
  const started = rt.now();
  const { view, configSource } = await computeDiff(args, rt);
  rt.stdout(render(view, args, rt));
  if (args.verbose) rt.stderr(`depward: config ${configSource ?? "built-in defaults"}, --fail-on ${args.failOn}
`);
  if (args.verbose) rt.stderr(`depward: ${view.packages.length} package change(s) checked in ${Math.round(rt.now() - started)} ms\n`);
  return diffExitCode(view, args.failOn);
}
