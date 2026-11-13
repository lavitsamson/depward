# depward with Codex CLI

Codex CLI uses depward through its **MCP server**. The agent gets three tools,
`check_install_command`, `check_packages`, and `diff_versions`, and the server's
instructions tell it to call them before installing or updating anything.

The MCP server is **advisory**: nothing stops the agent from running an install without
calling the tool first. depward has no adapter for Codex's own hooks yet
([roadmap](../ROADMAP.md)).

MCP config format checked against https://learn.chatgpt.com/docs/extend/mcp?surface=cli
(2026-11-11).

## 1. Install

```sh
npm install --global @depward/mcp@x.y.z   # pin an exact version
depward-mcp --version
```

## 2. Register the server

With the Codex CLI:

```sh
codex mcp add depward -- depward-mcp
```

Or edit `~/.codex/config.toml` (all projects), or `.codex/config.toml` in a trusted
project:

```toml
[mcp_servers.depward]
command = "depward-mcp"
```

## Config

The server reads `depward.config.json` (or the `"depward"` key of `package.json`) from
its working directory. Codex doesn't document a default for that, so set `cwd` to the
project, or pass the config file explicitly:

```toml
[mcp_servers.depward]
command = "depward-mcp"
cwd = "/path/to/your/project"
# or: args = ["--config", "/path/to/your/project/depward.config.json"]
```

A missing `--config` file stops the server at startup. The config is re-read on every
call, so edits apply without a restart.

Codex's defaults (10 s to start, 60 s per tool call) are enough. A check that can't
reach the registry doesn't hang: it applies the config's `onError` action (`ask` by
default).

## What the tools return

See [the Cursor page](cursor.md#what-the-tools-return). The tools behave the same in
every MCP client.
