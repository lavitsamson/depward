# 0004 — MCP server SDK: `@modelcontextprotocol/server` v2

- Status: accepted (2026-11-10)
- Date: 2026-11-10

## Context

`@depward/mcp` (M2.7) needs an MCP server implementation. The dependency allowlist in
CLAUDE.md approved `@modelcontextprotocol/sdk` and its peer `zod`, only in
`@depward/mcp`.

Since that was written, the official TypeScript SDK released v2 as its stable line and
split the package (<https://github.com/modelcontextprotocol/typescript-sdk>):
`@modelcontextprotocol/server` and `@modelcontextprotocol/client`, both built on
`@modelcontextprotocol/core`. `@modelcontextprotocol/sdk` is now the v1.x maintenance
line, with security and bug fixes for at least six months after the v2 release.

Their runtime trees, as published on 2026-10-23 (checked with `npm view`):

| Package | Direct runtime dependencies |
|---|---|
| `@modelcontextprotocol/sdk@1.32.2` | 17: ajv, ajv-formats, zod, cors, hono, @hono/node-server, jose, express, express-rate-limit, raw-body, content-type, cross-spawn, eventsource, eventsource-parser, pkce-challenge, json-schema-typed, zod-to-json-schema |
| `@modelcontextprotocol/server@2.4.0` | 2: `@modelcontextprotocol/core@2.4.0` (which depends only on `zod@^4.2`) and `zod@^4.2` |

depward is a supply-chain security tool and will be a target. Every package in its
runtime tree is attack surface for every user. A stdio server needs none of v1's HTTP
framework, OAuth, or process-spawning dependencies.

## Decision

`@depward/mcp` uses `@modelcontextprotocol/server@2.4.0` and `zod@4.6.7`, pinned
exactly. Its whole third-party runtime tree is therefore three packages:
`@modelcontextprotocol/server`, `@modelcontextprotocol/core`, and `zod`.
`@modelcontextprotocol/client@2.4.0` is a dev dependency, used only by tests. The
allowlist in CLAUDE.md is updated to name these packages instead of
`@modelcontextprotocol/sdk`.

The server is served with `serveStdio` (`@modelcontextprotocol/server/stdio`). Tool
schemas use `zod/v4` `z.object(…)`, as the v2 docs require
(<https://ts.sdk.modelcontextprotocol.io/v2/servers/tools.html>).

## Consequences

- A much smaller runtime tree than v1. cross-spawn, jose, eventsource, and
  pkce-challenge appear only in the dev-only client.
- v2's API differs from v1's: `registerTool` with `z.object` schemas, and `serveStdio`
  with a server factory instead of `StdioServerTransport` + `connect`. Examples written
  for v1 don't apply.
- zod v4 only. `@modelcontextprotocol/server` requires `zod@^4.2`.
- Upgrades follow the usual rules: exact pins, `minimumReleaseAge` of 7 days, and a
  check of the release notes, because v2 is younger than v1.
