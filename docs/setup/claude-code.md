# depward with Claude Code

Claude Code gets a **PreToolUse hook**: before Claude runs a Bash command, Claude Code
passes it to `depward hook claude`, which reads the command (it never runs it) and checks
every package it would install or execute.

Hook format checked against https://code.claude.com/docs/en/hooks (2026-11-10).

## 1. Install

```sh
npm install --global depward@x.y.z   # pin an exact version
depward --version
```

## 2. Register the hook

Add this to `.claude/settings.json` in the project (shared with the team), or to
`~/.claude/settings.json` (all your projects):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "depward hook claude", "timeout": 10 }]
      }
    ]
  }
}
```

If the file already has a `hooks` key, add the entry to its `PreToolUse` array. Restart
Claude Code, or open `/hooks` to confirm the hook is listed.

## What happens

| depward decides | Claude Code does |
|---|---|
| `deny` | Blocks the command. Claude is told why, with the real package name or an older version to use instead. |
| `ask` | Asks you to confirm. Claude sees the reason too. |
| `allow`, or the command installs nothing | depward prints nothing, and your normal permission rules apply. |

depward never answers "allow", because that would skip your permission prompt for
commands depward has no opinion on, like `rm -rf`.

The hook has a 4 s budget. If the registry is slow or unreachable it applies the
config's `onError` action (`ask` by default) instead of failing open. A cold cache can
hit this the first time a large package is checked. Every failure inside the hook (a bad
config, malformed input, a crash) becomes a decision, so the command never slips
through because depward broke.

## Config

The hook reads `depward.config.json` (or the `"depward"` key of `package.json`) from
`$CLAUDE_PROJECT_DIR`, the project root, even when Claude has `cd`-ed into a
subdirectory. To use a different file, add `--config <path>` to the command (relative to
the project root):

```json
{ "type": "command", "command": "depward hook claude --config tools/depward.json", "timeout": 10 }
```

## MCP server (optional)

The hook already covers Bash. The MCP server adds tools Claude can call on its own,
for example to check a package before adding it to `package.json` by hand. Install
`@depward/mcp` globally (pinned) and add it to `.mcp.json` in the project:

```json
{
  "mcpServers": {
    "depward": { "command": "depward-mcp" }
  }
}
```

The server reads the config from its working directory. If yours lives elsewhere, add
`"args": ["--config", "<absolute path>"]`. See the
[Cursor page](cursor.md#what-the-tools-return) for what the tools return.
