#!/usr/bin/env node
// `depward-mcp`: the depward MCP server over stdio. stdout carries protocol messages
// only; logs go to stderr. Serving: https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html

import { parseArgs } from "node:util";
import { createDiskCache, createRegistryClient, defaultCacheDir, loadConfig } from "@depward/core";
import { preloadAnalyzer } from "@depward/gate";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { VERSION, createDepwardServer } from "./index.ts";

const USAGE = `Usage: depward-mcp [options]

Serves depward's check_install_command and check_packages tools over MCP (stdio).

Options:
      --config <path>   Config file (default: depward.config.json, or the
                        "depward" key of package.json, in the current directory)
      --offline         Use only cached registry data (also: DEPWARD_OFFLINE=1)
  -h, --help            Show this help
  -v, --version         Show the version
`;

let values;
try {
  ({ values } = parseArgs({
    options: {
      config: { type: "string" },
      offline: { type: "boolean" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  }));
} catch (err) {
  process.stderr.write(`depward-mcp: ${(err as Error).message}\n\n${USAGE}`);
  process.exit(1);
}
if (values.help) {
  process.stdout.write(USAGE);
  process.exit(0);
}
if (values.version) {
  process.stdout.write(`${VERSION}\n`);
  process.exit(0);
}

const cwd = process.cwd();
// Fail fast on a broken config, before a client connects. Each call re-reads it.
const config = await loadConfig(cwd, values.config === undefined ? {} : { path: values.config }).catch((err: unknown) => {
  process.stderr.write(`depward-mcp: ${(err as Error).message}\n`);
  process.exit(1);
});
const registry = createRegistryClient({
  cwd,
  cache: createDiskCache(defaultCacheDir()),
  ...(config.registry === undefined ? {} : { registry: config.registry }),
  ...(values.offline ? { offline: true } : {}),
});
// A long-running server pays the analyzer's load time once, before the first call.
await preloadAnalyzer();

const handle = serveStdio(() =>
  createDepwardServer({ registry, cwd, version: VERSION, ...(values.config === undefined ? {} : { configPath: values.config }) }),
);
process.stderr.write(`depward-mcp ${VERSION}: serving on stdio (config: ${config.source ?? "built-in defaults"})\n`);
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void handle.close().finally(() => process.exit(0));
  });
}
