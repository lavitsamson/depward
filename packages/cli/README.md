# depward

Protects JavaScript projects, and the AI coding agents working in them, from risky npm dependencies. Reads registry metadata and statically analyzes tarballs; never runs package code.

> **Status:** pre-release (Phase 2). `depward check` works; the Claude Code hook
> (`depward hook claude`) comes next. See the [roadmap](../../docs/ROADMAP.md).

## Example

```sh
npm install --global depward@0.0.0   # pin an exact version

depward check left-pad@1.3.0 react-codeshift
# depward: deny (2 packages: 1 deny, 1 allow)
#
#   ALLOW  left-pad@1.3.0
#
#   DENY   react-codeshift@1.0.0
#          known-hallucinated-name: react-codeshift is a package name AI models are documented to hallucinate. Did you mean jscodeshift?
#          low-downloads: react-codeshift has 11 downloads in the last week (minimum 500).
echo $?   # 20

depward check --command "npm i -D vitest && npx create-vite@latest app"   # reads the command, never runs it
```

## `depward check`

```
depward check [options] <spec...>
depward check [options] --command "<shell command>"

  -c, --command <cmd>   Check a shell command instead of specs
      --format <fmt>    terminal (default), json, markdown, sarif
      --json            Same as --format json
      --config <path>   Config file (default: depward.config.json, or the
                        "depward" key of package.json, in the current directory)
      --offline         Use only cached registry data (also: DEPWARD_OFFLINE=1)
      --verbose         Also show findings the policy allows, and timing
```

Exit codes: `0` allow, `10` ask, `20` deny, `1` error (bad arguments, invalid config).
A registry outage is not an error: it costs the config's `onError` action (`ask` by
default).

`--format json` prints the decision (`decisionVersion: 1`): the overall `action`, one
`reasons` line per cause, and per package the resolved version, action, findings with
the action each one got, and failed lookups. `sarif` and `markdown` contain every
finding, for CI and pull-request comments. Every finding ID is described in
[docs/findings.md](../../docs/findings.md).

## Config

`depward.config.json` (or a `"depward"` key in package.json):

```json
{
  "policy": { "version-too-new": "allow" },
  "thresholds": { "minVersionAgeDays": 7, "minPackageAgeDays": 30, "minWeeklyDownloads": 500 },
  "allow": ["@myorg/*"],
  "deny": ["event-stream@3.3.6"],
  "onError": "ask"
}
```

Requires Node.js >= 22.15. ESM only. MIT licensed.
