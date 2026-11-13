// `depward caps check`: CI gate on unapproved capabilities. Spec: docs/specs/caps.md
// § Check details. Reports use the diff renderers.

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { capsCheckExitCode, checkCapabilities, type CapsCheckReport } from "@depward/caps";
import { DepwardError, REPORT_FORMATS, colorEnabled, escapeUnsafe, type ReportFormat } from "@depward/core";
import { FAIL_ON_LEVELS, reachesFailOn, serializeDiff, type FailOn } from "@depward/diff";
import { createPolicy } from "@depward/gate";
import { COMMON_OPTIONS, parseCapsFile, parseConcurrency, plural, readCapsFile, retryHint } from "./caps-shared.ts";
import { openContext } from "./context.ts";
import { renderDiffMarkdown } from "./diff-markdown.ts";
import { renderDiffSarif, renderDiffTerminal } from "./diff-render.ts";
import { UsageError, type Runtime } from "./runtime.ts";

const TITLE = "depward caps check";

function render(report: CapsCheckReport, format: ReportFormat, failOn: FailOn, verbose: boolean, rt: Runtime): string {
  const tool = { name: "depward", version: rt.version };
  switch (format) {
    case "json": {
      const doc = serializeDiff(report, tool, { failOn, failed: capsCheckExitCode(report, failOn) === 20 });
      return `${JSON.stringify({ ...doc, counts: report.counts }, null, 2)}\n`;
    }
    case "markdown":
      return renderDiffMarkdown(report, { title: TITLE });
    case "sarif":
      return renderDiffSarif(report, tool);
    case "terminal": {
      const text = renderDiffTerminal(report, { color: colorEnabled(rt.env, rt.isTTY), verbose, title: TITLE });
      const summary = `${plural(report.counts.checked, "package")} checked; ${plural(report.counts.unapproved, "package")} with unapproved capabilities.`;
      const next = report.counts.unapproved > 0 ? "\nReview the uses, then run: depward caps approve <name>[@version] [--cap <cap>] [--reason <text>]" : "";
      return `${text}\n${summary}${next}\n`;
    }
  }
}

/** Runs `depward caps check` and returns the exit code. */
export async function runCapsCheck(argv: string[], rt: Runtime): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: { ...COMMON_OPTIONS, format: { type: "string" }, json: { type: "boolean" }, "fail-on": { type: "string" }, verbose: { type: "boolean" } },
  });
  if (positionals.length > 0) throw new UsageError("caps check takes no package arguments");
  let format: ReportFormat = "terminal";
  if (values.format !== undefined) {
    if (!(REPORT_FORMATS as readonly string[]).includes(values.format)) throw new UsageError(`--format must be one of ${REPORT_FORMATS.join(", ")}`);
    format = values.format as ReportFormat;
  }
  if (values.json) {
    if (values.format !== undefined && values.format !== "json") throw new UsageError(`--json conflicts with --format ${values.format}`);
    format = "json";
  }
  const failOn = values["fail-on"] ?? "critical";
  if (!(FAIL_ON_LEVELS as readonly string[]).includes(failOn)) throw new UsageError(`--fail-on must be one of ${FAIL_ON_LEVELS.join(", ")}`);
  const concurrency = parseConcurrency(values.concurrency);
  const capsFile = parseCapsFile(values["caps-file"]);

  const caps = await readCapsFile(resolve(rt.cwd, capsFile));
  if (caps === null) throw new DepwardError("NOT_FOUND", `${escapeUnsafe(capsFile, 200)} not found; create it with "depward caps scan"`);
  const { config, registry, analysisCache, overrides } = await openContext(rt, { config: values.config, offline: values.offline ?? false });
  const report = await checkCapabilities({
    cwd: rt.cwd,
    registry,
    caps,
    policy: createPolicy(config),
    concurrency,
    ...(analysisCache === undefined ? {} : { analysisCache }),
    ...(overrides.tarLimits === undefined ? {} : { tarLimits: overrides.tarLimits }),
    ...(overrides.analyze === undefined ? {} : { analyze: overrides.analyze }),
  });
  rt.stdout(render(report, format, failOn as FailOn, values.verbose ?? false, rt));
  const code = capsCheckExitCode(report, failOn as FailOn);
  if (code === 1 && !reachesFailOn(report.packages, failOn as FailOn)) {
    rt.stderr(retryHint(report.packages.flatMap((p) => p.errors.map((e) => e.code))));
  }
  return code;
}
