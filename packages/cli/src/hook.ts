// `depward hook <agent>`: reads an agent's hook payload on stdin and writes the agent's
// decision format on stdout. Spec: docs/specs/gate.md §Claude Code hook adapter.
//
// stdout carries only the decision; logs go to stderr. The exit code is always the
// adapter's (0 for Claude Code): a crash, bad input, an invalid config, or running out
// of time becomes an `onError` decision (default ask), never a silent pass.

import { parseArgs } from "node:util";
import {
  createDiskCache,
  createRegistryClient,
  defaultCacheDir,
  escapeUnsafe,
  isDepwardError,
  loadConfig,
  type DepwardConfig,
  type PolicyAction,
} from "@depward/core";
import { HOOK_ADAPTERS, checkCommand, hookVerdict, type HookAdapter, type HookVerdict } from "@depward/gate";
import { EXIT, UsageError, type Runtime } from "./runtime.ts";

export const HOOK_USAGE: string = `Usage: depward hook <agent> [options]

Reads the agent's hook input on stdin and answers in its format on stdout. Commands
with nothing risky to install get no output, so the agent's own permission rules
decide. Agents: ${Object.keys(HOOK_ADAPTERS).join(", ")}.

Options:
      --config <path>   Config file (default: depward.config.json, or the
                        "depward" key of package.json, in the project directory)
      --offline         Use only cached registry data (also: DEPWARD_OFFLINE=1)
  -h, --help            Show this help
`;

/** Total time for one hook call (gate.md: 4 s, below the 5 s cold-check target). */
export const HOOK_BUDGET_MS = 4000;
const MAX_STDIN_BYTES = 1024 * 1024;

/** Reads all of stdin as UTF-8, up to 1 MB. */
export async function readStdin(stream: NodeJS.ReadableStream = process.stdin): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
    size += buf.byteLength;
    if (size > MAX_STDIN_BYTES) throw new UsageError(`hook input is larger than ${MAX_STDIN_BYTES} bytes`);
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const errorText = (err: unknown): string =>
  escapeUnsafe(isDepwardError(err) ? `${err.code}: ${err.message}` : err instanceof Error ? err.message : String(err), 300);

function failure(action: PolicyAction, problem: string): HookVerdict {
  return { action, reason: `depward: ${problem} (onError: ${action}). Check the command with \`depward check --command …\`, or ask the user.` };
}

async function decide(adapter: HookAdapter, input: string, args: { config?: string; offline: boolean }, rt: Runtime): Promise<HookVerdict> {
  let payload: unknown;
  try {
    payload = JSON.parse(input);
  } catch {
    return failure("ask", "the hook input is not valid JSON");
  }
  const parsed = adapter.parse(payload);
  if (parsed.kind === "ignore") return { action: "allow", reason: "" };
  if (parsed.kind === "invalid") return failure("ask", parsed.problem);

  // The config lives in the project root. Claude Code sets CLAUDE_PROJECT_DIR for hooks;
  // the payload's cwd may be a subdirectory the agent cd'ed into.
  const projectDir = rt.env["CLAUDE_PROJECT_DIR"] || parsed.request.cwd || rt.cwd;
  let config: DepwardConfig;
  try {
    config = await loadConfig(projectDir, args.config === undefined ? {} : { path: args.config });
  } catch (err) {
    return failure("ask", `the config can't be loaded: ${errorText(err)}`);
  }

  const budget = rt.hookBudgetMs ?? HOOK_BUDGET_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), budget);
  });
  try {
    const registry = rt.gate?.registry ?? createRegistryClient({
      cwd: projectDir,
      env: rt.env,
      cache: createDiskCache(defaultCacheDir(rt.env)),
      ...(config.registry === undefined ? {} : { registry: config.registry }),
      ...(args.offline ? { offline: true } : {}),
    });
    const decision = await Promise.race([checkCommand(parsed.request.command, { ...rt.gate, registry, config }), timeout]);
    if (decision === null) return failure(config.onError, `the check didn't finish within ${budget / 1000} s`);
    return hookVerdict(decision);
  } catch (err) {
    return failure(config.onError, `the check failed: ${errorText(err)}`);
  } finally {
    clearTimeout(timer);
  }
}

/** Runs `depward hook <agent>` and returns the exit code. */
export async function runHook(argv: string[], rt: Runtime): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      config: { type: "string" },
      offline: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    rt.stdout(HOOK_USAGE);
    return EXIT.allow;
  }
  const [name, ...extra] = positionals;
  if (name === undefined) throw new UsageError("name the agent: depward hook claude");
  if (extra.length > 0) throw new UsageError(`unexpected argument ${JSON.stringify(extra[0])}`);
  const adapter = Object.hasOwn(HOOK_ADAPTERS, name) ? HOOK_ADAPTERS[name] : undefined;
  if (adapter === undefined) throw new UsageError(`unknown agent ${JSON.stringify(name)}`);

  let verdict: HookVerdict;
  try {
    const input = await (rt.stdin ?? readStdin)();
    verdict = await decide(adapter, input, { ...(values.config === undefined ? {} : { config: values.config }), offline: values.offline ?? false }, rt);
  } catch (err) {
    verdict = failure("ask", `the hook failed: ${errorText(err)}`);
  }
  if (verdict.action !== "allow") rt.stderr(`${verdict.reason}\n`);
  const response = adapter.respond(verdict);
  rt.stdout(response.stdout);
  return response.exitCode;
}
