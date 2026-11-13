# @depward/mcp

An MCP server that lets AI coding agents check packages and install commands with depward before running them.

> **Status:** pre-release (Phase 2). `check_install_command` and `check_packages` work;
> `diff_versions` comes in Phase 3. See the [roadmap](../../docs/ROADMAP.md).

## Example

Register the server with your agent ([setup for Claude Code, Cursor, and Codex CLI](../../docs/setup/README.md)). For example, in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "depward": { "command": "depward-mcp" }
  }
}
```

Install it globally at a pinned version (`npm i -g @depward/mcp@x.y.z`) rather than
through `npx`, which would itself be an unchecked install.

Or embed it:

```js
import { createRegistryClient } from "@depward/core";
import { createDepwardServer, VERSION } from "@depward/mcp";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

const registry = createRegistryClient();
serveStdio(() => createDepwardServer({ registry, version: VERSION }));
```

## Tools

- **`check_install_command({ command })`**: reads a shell command (never runs it) and
  checks every package it would install or execute.
- **`check_packages({ specs })`**: checks package specs such as `left-pad@1.3.0`,
  `@scope/name@^2`, or `alias@npm:real@1`.

Each tool returns `allow`, `ask`, or `deny`. The text block explains why and suggests
the real package or an older version. `structuredContent` holds the full decision
(the same JSON as `depward check --json`). Both tools are read-only.

When a package is already in the project's lockfile at another version, both tools
also diff the requested version against the locked one (`@depward/diff`), so an update
that adds an install script, network use, or obfuscation is flagged.

The project's `depward.config.json` (or the `"depward"` key of package.json) in the
server's working directory applies, and it is re-read on every call. Options:
`depward-mcp --config <path>` and `--offline` (or `DEPWARD_OFFLINE=1`).

## Dependencies

Besides depward's own packages, the runtime tree is `@modelcontextprotocol/server`,
`@modelcontextprotocol/core`, and `zod`, all pinned exactly
([ADR 0004](../../docs/adr/0004-mcp-sdk-v2.md)).

Requires Node.js >= 22.15. ESM only. MIT licensed.
