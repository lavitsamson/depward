// `depward check`: package specs or a shell command in, a decision out.
// Spec: docs/specs/gate.md §CLI. Argument parsing uses node:util parseArgs
// (https://nodejs.org/api/util.html#utilparseargsconfig).

import { parseArgs } from "node:util";
import { REPORT_FORMATS, colorEnabled, renderSarif, type ReportFormat } from "@depward/core";
import { checkCommand, checkSpecs, decisionFindings, serializeDecision, type Decision } from "@depward/gate";
import { openContext, updateDiff } from "./context.ts";
import { renderDecisionMarkdown, renderDecisionTerminal } from "./render.ts";
import { EXIT, UsageError, type Runtime } from "./runtime.ts";

export const CHECK_USAGE = `Usage: depward check [options] <spec...>
       depward check [options] --command "<shell command>"

Checks packages before they are installed. Specs are written as for npm install
(left-pad@1.3.0, @scope/name@^2, alias@npm:real@1). With --command, the command is
read (never run) and every package it would install or execute is checked.

Options:
  -c, --command <cmd>   Check a shell command instead of specs
      --format <fmt>    terminal (default), json, markdown, sarif
      --json            Same as --format json
      --config <path>   Config file (default: depward.config.json, or the
                        "depward" key of package.json, in the current directory)
      --offline         Use only cached registry data (also: DEPWARD_OFFLINE=1)
      --verbose         Also show findings the policy allows, and timing
  -h, --help            Show this help

Exit codes: 0 allow, 10 ask, 20 deny, 1 error.
`;

interface CheckArgs {
  readonly specs: string[];
  readonly command: string | undefined;
  readonly format: ReportFormat;
  readonly config: string | undefined;
  readonly offline: boolean;
  readonly verbose: boolean;
  readonly help: boolean;
}

function parse(argv: string[]): CheckArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      command: { type: "string", short: "c" },
      format: { type: "string" },
      json: { type: "boolean" },
      config: { type: "string" },
      offline: { type: "boolean" },
      verbose: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  let format: ReportFormat = "terminal";
  if (values.format !== undefined) {
    if (!(REPORT_FORMATS as readonly string[]).includes(values.format)) {
      throw new UsageError(`--format must be one of ${REPORT_FORMATS.join(", ")}`);
    }
    format = values.format as ReportFormat;
  }
  if (values.json) {
    if (values.format !== undefined && values.format !== "json") throw new UsageError("--json conflicts with --format " + values.format);
    format = "json";
  }
  const args: CheckArgs = {
    specs: positionals,
    command: values.command,
    format,
    config: values.config,
    offline: values.offline ?? false,
    verbose: values.verbose ?? false,
    help: values.help ?? false,
  };
  if (args.help) return args;
  if (args.command !== undefined && args.specs.length > 0) throw new UsageError("give package specs or --command, not both");
  if (args.command === undefined && args.specs.length === 0) throw new UsageError("nothing to check: give package specs or --command");
  return args;
}

function render(decision: Decision, args: CheckArgs, rt: Runtime): string {
  switch (args.format) {
    case "json":
      return `${JSON.stringify(serializeDecision(decision, { name: "depward", version: rt.version }), null, 2)}\n`;
    case "markdown":
      return renderDecisionMarkdown(decision);
    case "sarif":
      return renderSarif(decisionFindings(decision), { tool: { name: "depward", version: rt.version } });
    case "terminal":
      return renderDecisionTerminal(decision, { color: colorEnabled(rt.env, rt.isTTY), verbose: args.verbose });
  }
}

/** Runs `depward check` and returns the exit code. */
export async function runCheck(argv: string[], rt: Runtime): Promise<number> {
  const args = parse(argv);
  if (args.help) {
    rt.stdout(CHECK_USAGE);
    return EXIT.allow;
  }

  const started = rt.now();
  const { config, registry, analysisCache, overrides } = await openContext(rt, args);
  const opts = {
    ...(analysisCache === undefined ? {} : { analysisCache }),
    diffUpdate: updateDiff(rt.cwd, registry, analysisCache, overrides),
    ...overrides,
    registry,
    config,
  };
  const decision = args.command === undefined ? await checkSpecs(args.specs, opts) : await checkCommand(args.command, opts);

  rt.stdout(render(decision, args, rt));
  if (args.verbose) {
    const source = config.source ?? "built-in defaults";
    rt.stderr(`depward: ${decision.packages.length} package(s) checked in ${Math.round(rt.now() - started)} ms (config: ${source})\n`);
  }
  return EXIT[decision.action];
}
