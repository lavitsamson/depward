// `depward caps approve`: record approvals in the capability lockfile. Spec:
// docs/specs/caps.md § Approve details.

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { approveCapabilities, parseTarget, serializeCapsLockfile } from "@depward/caps";
import { escapeUnsafe, gitUserName } from "@depward/core";
import { COMMON_OPTIONS, parseCapsFile, parseConcurrency, plural, readCapsFile, retryHint, writeAtomic } from "./caps-shared.ts";
import { openContext } from "./context.ts";
import { EXIT, UsageError, type Runtime } from "./runtime.ts";

/** Runs `depward caps approve` and returns the exit code. */
export async function runCapsApprove(argv: string[], rt: Runtime): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: { ...COMMON_OPTIONS, cap: { type: "string", multiple: true }, reason: { type: "string" }, by: { type: "string" } },
  });
  if (positionals.length === 0) throw new UsageError("give at least one package: caps approve <name>[@version]");
  const targets = positionals.map((arg) => {
    const t = parseTarget(arg);
    if (t.name === "" || t.version === "") throw new UsageError(`invalid package ${JSON.stringify(escapeUnsafe(arg, 100))}`);
    return t;
  });
  if (values.reason === "") throw new UsageError("--reason needs text");
  if (values.by === "") throw new UsageError("--by needs a name");
  const concurrency = parseConcurrency(values.concurrency);
  const capsFile = parseCapsFile(values["caps-file"]);
  const path = resolve(rt.cwd, capsFile);

  const caps = await readCapsFile(path);
  const by = values.by ?? (await gitUserName(rt.cwd)) ?? "manual";
  const { registry, analysisCache, overrides } = await openContext(rt, { config: values.config, offline: values.offline ?? false });
  const result = await approveCapabilities({
    cwd: rt.cwd,
    registry,
    caps,
    targets,
    by,
    concurrency,
    ...(values.cap === undefined ? {} : { capabilities: values.cap }),
    ...(values.reason === undefined ? {} : { reason: values.reason }),
    ...(analysisCache === undefined ? {} : { analysisCache }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
    ...(overrides.tarLimits === undefined ? {} : { tarLimits: overrides.tarLimits }),
    ...(overrides.analyze === undefined ? {} : { analyze: overrides.analyze }),
  });

  if (result.errors.length > 0) {
    for (const e of result.errors) rt.stderr(`depward: ${e.code}: ${escapeUnsafe(e.message, 500)}\n`);
    rt.stderr(`depward: ${plural(result.errors.length, "problem")}; nothing was written\n`);
    rt.stderr(retryHint(result.errors.map((e) => e.code)));
    return EXIT.error;
  }

  await writeAtomic(path, serializeCapsLockfile(result.lockfile));
  const lines = result.approved.map((a) => {
    const key = escapeUnsafe(a.key, 214);
    const head = a.capabilities.length === 0 ? `Recorded ${key} (uses no capabilities).` : `Approved ${a.capabilities.join(", ")} for ${key}.`;
    const notes = [
      ...(a.unapproved.length === 0 ? [] : [`Still unapproved: ${a.unapproved.join(", ")}.`]),
      ...(a.notDetected.length === 0 ? [] : [`Not seen by static analysis (approved for runtime enforcement): ${a.notDetected.join(", ")}.`]),
    ];
    return [head, ...notes].join(" ");
  });
  rt.stdout(`${lines.join("\n")}\nWrote ${escapeUnsafe(capsFile, 200)}.\n`);
  return EXIT.allow;
}
