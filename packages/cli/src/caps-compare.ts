// `depward caps compare`: what `@depward/caps/register` observed at runtime vs the
// capability lockfile. Spec: docs/specs/caps.md § Runtime details.

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { DEFAULT_OBSERVED_PATH, capsCheckExitCode, compareObserved, parseObserved } from "@depward/caps";
import { DepwardError, escapeUnsafe, loadConfig } from "@depward/core";
import { createPolicy } from "@depward/gate";
import { REPORT_OPTIONS, parseReportArgs, renderCapsReport } from "./caps-check.ts";
import { COMMON_OPTIONS, parseCapsFile, readCapsFile } from "./caps-shared.ts";
import { UsageError, type Runtime } from "./runtime.ts";

/** Runs `depward caps compare` and returns the exit code. */
export async function runCapsCompare(argv: string[], rt: Runtime): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: { ...COMMON_OPTIONS, ...REPORT_OPTIONS, observed: { type: "string" } },
  });
  if (positionals.length > 0) throw new UsageError("caps compare takes no package arguments");
  const { format, failOn } = parseReportArgs(values);
  const capsFile = parseCapsFile(values["caps-file"]);
  const observedPath = values.observed ?? DEFAULT_OBSERVED_PATH;
  if (observedPath === "") throw new UsageError("--observed needs a path");

  const caps = await readCapsFile(resolve(rt.cwd, capsFile));
  if (caps === null) throw new DepwardError("NOT_FOUND", `${escapeUnsafe(capsFile, 200)} not found; create it with "depward caps scan"`);
  let text: string;
  try {
    text = await readFile(resolve(rt.cwd, observedPath), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    throw new DepwardError("NOT_FOUND", `${escapeUnsafe(observedPath, 200)} not found; run the app with "node --import @depward/caps/register" first`);
  }
  const observed = parseObserved(text);
  if (observed === null) throw new DepwardError("INVALID_ARGUMENT", `${escapeUnsafe(observedPath, 200)} is not a valid observed-capabilities file`);

  const config = await loadConfig(rt.cwd, values.config === undefined ? {} : { path: values.config });
  const report = compareObserved(observed, caps, { policy: createPolicy(config) });
  rt.stdout(renderCapsReport(report, format, failOn, values.verbose ?? false, rt, "depward caps compare"));
  return capsCheckExitCode(report, failOn);
}
