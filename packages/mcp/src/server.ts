// The depward MCP server: `check_packages` and `check_install_command`.
// Spec: docs/specs/gate.md §MCP server. SDK: @modelcontextprotocol/server v2 (ADR 0004).
// API checked 2026-11-10 against https://ts.sdk.modelcontextprotocol.io/v2/servers/tools.html
// and the package's type declarations: registerTool(name, { title, description,
// inputSchema: z.object(…), outputSchema, annotations }, handler) returning
// { content, structuredContent, isError }.

import { escapeUnsafe, isDepwardError, loadConfig, type DepwardConfig, type RegistryClient } from "@depward/core";
import { createUpdateDiff } from "@depward/diff";
import { checkCommand, checkSpecs, serializeDecision, type Decision, type GateOptions } from "@depward/gate";
import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

/** Options for {@link createDepwardServer}. */
export interface DepwardServerOptions {
  /** One registry client for the server's lifetime, so its in-memory cache is shared across calls. */
  registry: RegistryClient;
  /** Where the project config is looked up (`depward.config.json`, package.json). Default `process.cwd()`. */
  cwd?: string;
  /** Read this config file instead (relative to `cwd`). */
  configPath?: string;
  /** The server version reported to clients and in JSON results. */
  version: string;
  /** Overrides for the gate (data files, clock), for tests. */
  gate?: Partial<GateOptions>;
}

const INSTRUCTIONS = `depward checks npm packages before they are installed: whether they exist (AI models often invent package names), how new and popular they are, who published them, and what their tarball does (install scripts, credential theft, obfuscation). It never runs package code.

Call check_install_command BEFORE running any command that installs or executes packages (npm/pnpm/yarn/bun install or add, npx, pnpm dlx, bunx, create/init). If the result is "deny", do not run the command: switch to the suggested package or version, or ask the user. If it is "ask", tell the user what depward found and let them decide.`;

const ACTION = z.enum(["allow", "ask", "deny"]);

const DECISION_OUTPUT = z.object({
  decisionVersion: z.literal(1),
  tool: z.object({ name: z.string(), version: z.string().optional() }),
  action: ACTION,
  reasons: z.array(z.string()),
  packages: z.array(z.looseObject({ name: z.string(), action: ACTION })),
  findings: z.array(z.looseObject({ id: z.string(), action: ACTION })),
});

const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

function label(p: Decision["packages"][number]): string {
  if (p.version !== null) return p.update === null ? `${p.name}@${p.version}` : `${p.name}@${p.version} (update from ${p.update.from})`;
  return p.source === "registry" ? `${p.name}@${p.range}` : p.range;
}

/** The text block a model reads: the decision, its causes, and what to do next. */
export function decisionText(decision: Decision): string {
  const n = decision.packages.length;
  const lines = [`depward: ${decision.action} (${n === 0 ? "nothing to install" : `${n} package${n === 1 ? "" : "s"} checked`})`];
  for (const r of decision.reasons) lines.push(`- ${r}`);
  for (const p of decision.packages) {
    if (p.action === "allow") continue;
    const s = p.suggestion;
    if (s.name !== undefined) lines.push(`Suggested instead of ${escapeUnsafe(label(p), 200)}: ${escapeUnsafe(s.name, 200)}`);
    else if (s.version !== undefined) lines.push(`Suggested instead of ${escapeUnsafe(label(p), 200)}: ${escapeUnsafe(`${p.name}@${s.version}`, 200)}`);
  }
  if (decision.action === "deny") lines.push("Do not run this install. Use a suggested alternative, or ask the user.");
  else if (decision.action === "ask") lines.push("Tell the user what depward found and let them decide before installing.");
  else lines.push("depward found nothing that blocks this install.");
  return lines.join("\n");
}

function failure(err: unknown): { content: [{ type: "text"; text: string }]; isError: true } {
  const text = isDepwardError(err) ? `${err.code}: ${err.message}` : err instanceof Error ? err.message : String(err);
  return { content: [{ type: "text", text: `depward: ${escapeUnsafe(text, 500)}` }], isError: true };
}

/**
 * Builds an MCP server with depward's tools. The config is re-read on every call, so
 * edits to `depward.config.json` apply without restarting the server.
 */
export function createDepwardServer(opts: DepwardServerOptions): McpServer {
  const server = new McpServer({ name: "depward", version: opts.version }, { instructions: INSTRUCTIONS });
  const cwd = opts.cwd ?? process.cwd();
  const config = (): Promise<DepwardConfig> => loadConfig(cwd, opts.configPath === undefined ? {} : { path: opts.configPath });

  async function respond(run: (gate: GateOptions) => Promise<Decision>) {
    try {
      const gate = opts.gate ?? {};
      // The update path (ADR 0006): a fresh callback per call re-reads the lockfiles.
      const diffUpdate = createUpdateDiff({
        cwd,
        registry: opts.registry,
        ...(gate.analysisCache === undefined ? {} : { analysisCache: gate.analysisCache }),
        ...(gate.now === undefined ? {} : { now: gate.now }),
        ...(gate.tarLimits === undefined ? {} : { tarLimits: gate.tarLimits }),
        ...(gate.analyze === undefined ? {} : { analyze: gate.analyze }),
      });
      const decision = await run({ diffUpdate, ...gate, registry: opts.registry, config: await config() });
      return {
        content: [{ type: "text" as const, text: decisionText(decision) }],
        structuredContent: { ...serializeDecision(decision, { name: "depward", version: opts.version }) },
      };
    } catch (err) {
      return failure(err);
    }
  }

  server.registerTool(
    "check_install_command",
    {
      title: "Check an install command",
      description:
        "Call this BEFORE running any shell command that installs or runs npm packages (npm/pnpm/yarn/bun install or add, npx, pnpm dlx, bunx, create/init). " +
        "depward reads the command (it never runs it) and checks every package it would install: hallucinated or missing names, typosquats, very new packages and versions, publisher changes, and tarball behavior such as install scripts and credential theft. " +
        'Returns "allow", "ask", or "deny" with reasons. On "deny", do not run the command; use the suggested package or version instead, or ask the user.',
      inputSchema: z.object({
        command: z.string().min(1).max(10_000).describe("The full shell command, exactly as it would be run."),
      }),
      outputSchema: DECISION_OUTPUT,
      annotations: ANNOTATIONS,
    },
    ({ command }) => respond((gate) => checkCommand(command, gate)),
  );

  server.registerTool(
    "check_packages",
    {
      title: "Check npm packages",
      description:
        "Check npm packages before adding them as dependencies. Specs are written as for npm install: name, name@range, @scope/name@tag, alias@npm:real@range. " +
        'Returns "allow", "ask", or "deny" per package with reasons. Prefer check_install_command when you have the actual command. On "deny", use the suggested alternative.',
      inputSchema: z.object({
        specs: z.array(z.string().min(1).max(500)).min(1).max(50).describe('Package specs, e.g. ["left-pad@1.3.0", "@scope/name"].'),
      }),
      outputSchema: DECISION_OUTPUT,
      annotations: ANNOTATIONS,
    },
    ({ specs }) => respond((gate) => checkSpecs(specs, gate)),
  );

  return server;
}
