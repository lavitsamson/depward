# depward with Cursor

Cursor uses depward through its **MCP server**. The agent gets three tools,
`check_install_command`, `check_packages`, and `diff_versions`, and the server's
instructions tell it to call them before installing or updating anything.

The MCP server is **advisory**: nothing stops the agent from running an install without
calling the tool first. depward has no adapter for Cursor's own hooks yet
([roadmap](../ROADMAP.md)).

MCP config format checked against https://cursor.com/docs/context/mcp (2026-11-11).

## 1. Install

```sh
npm install --global @depward/mcp@x.y.z   # pin an exact version
depward-mcp --version
```

## 2. Register the server

Add this to `.cursor/mcp.json` in the project, or to `~/.cursor/mcp.json` (all
projects):

```json
{
  "mcpServers": {
    "depward": {
      "type": "stdio",
      "command": "depward-mcp"
    }
  }
}
```

If Cursor can't find `depward-mcp`, give its full path: `$(npm prefix -g)/bin/depward-mcp`
on macOS and Linux, or `depward-mcp.cmd` directly in the `npm prefix -g` folder on
Windows.

Open Cursor Settings → MCP and check that `depward` is listed with two tools.

## Config

Cursor doesn't document which working directory it starts MCP servers in, so point the
server at the project's config explicitly. In the project's `.cursor/mcp.json`,
`${workspaceFolder}` is the folder that contains `.cursor/`:

```json
{
  "mcpServers": {
    "depward": {
      "type": "stdio",
      "command": "depward-mcp",
      "args": ["--config", "${workspaceFolder}/depward.config.json"]
    }
  }
}
```

Use `--config` only when that file exists. A missing config file stops the server at
startup. The config is re-read on every call, so edits apply without a restart.

## What the tools return

Each call returns `allow`, `ask`, or `deny` with a reason per finding. For `deny` the
text tells the agent not to run the command and names the real package or an older
version to use instead. For `ask` it tells the agent to check with you first. The full
decision (the same JSON as `depward check --json`) is in the result's
`structuredContent`. `diff_versions` returns a risk level (`info` to `critical`) for
an update instead. All tools are read-only: they read the command, never run it.

## Claude Code hooks in Cursor

Cursor can import hooks from `.claude/settings.json`
([docs](https://cursor.com/docs/reference/third-party-hooks)). **This is untested and
not supported.** Cursor maps Claude Code's `Bash` tool to its own `Shell` tool and
doesn't document the input it sends, while `depward hook claude` acts only on input
naming the `Bash` tool and stays silent otherwise. Under Cursor it may let every command
through. Don't rely on it. Use the MCP server.
