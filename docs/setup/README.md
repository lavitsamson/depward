# Setting up depward with a coding agent

depward checks the packages a command would install before an agent runs it. It reads
the command and registry metadata and statically analyzes tarballs. It never runs package
code. There are two ways to connect it to an agent:

| | How it works | Enforced? | Agents |
|---|---|---|---|
| **Hook** (`depward hook claude`) | The agent runs depward before every shell command. A `deny` blocks the command. | Yes. The agent can't skip it. | [Claude Code](claude-code.md) |
| **MCP server** (`depward-mcp`) | The agent gets `check_install_command` and `check_packages` tools and is told to call them before installing. | No. The agent chooses to call the tools. | [Claude Code](claude-code.md#mcp-server-optional), [Cursor](cursor.md), [Codex CLI](codex.md), and any MCP client |

Use the hook where one exists. Cursor and Codex CLI have hook systems of their own, but
depward has no adapter for them yet ([roadmap](../ROADMAP.md)), so for those agents
these pages cover only the MCP server.

## Install

Install a pinned version globally, then point the agent at the binaries:

```sh
npm install --global depward@x.y.z        # provides `depward` (CLI and hook)
npm install --global @depward/mcp@x.y.z   # provides `depward-mcp`
```

Don't run depward through `npx` in an agent config. `npx` downloads and runs whatever
version is current, which is the unchecked install depward exists to prevent. Requires
Node.js >= 22.15.

## Config

All adapters read the same optional `depward.config.json` (or a `"depward"` key in
`package.json`). Each agent page says which directory that is. Without a config file,
the built-in defaults apply. The options are listed in the
[CLI README](../../packages/cli/README.md#config). Finding IDs are described in
[findings.md](../findings.md).

## Try it

Any of these setups can be checked by asking the agent to install a known hallucinated
package name, such as `npm install react-codeshift`. depward should deny it and suggest
`jscodeshift`. From a terminal you can see the same decision with:

```sh
depward check --command "npm install react-codeshift"
```
