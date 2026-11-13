# depward

Protects JavaScript projects, and the AI coding agents working in them, from risky npm dependencies. Reads registry metadata and statically analyzes tarballs; never runs package code.

> **Status:** pre-release (Phase 4). `depward check`, `depward diff`, `depward caps`
> (`scan`, `check`, `approve`, `compare`), and the Claude Code hook (`depward hook claude`) work. Agent setup: [docs/setup](../../docs/setup/README.md). See the
> [roadmap](../../docs/ROADMAP.md).

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

## `depward diff`

```
depward diff [options] <name> <fromVersion> <toVersion>
depward diff --lockfile [--base <ref>] [options]

      --lockfile          Diff the lockfile changes instead of one package
      --base <ref>        Git ref to compare with (default origin/HEAD)
      --head <ref>        Read the lockfiles at this ref instead of the working tree
      --format <fmt>      terminal (default), json, markdown, sarif
      --fail-on <level>   Exit 20 at this risk: critical (default), high, medium,
                          low, info, or none
      --concurrency <n>   Packages checked at once (default 8)
      --offline, --config, --verbose, --json   As for check
```

Shows what a new version can do that the old one couldn't: new install scripts,
network use, secret reads, endpoints, obfuscated code, dependencies, a new publisher, or
lost provenance. With `--lockfile`, every lockfile in the current directory is compared
with the same file at the merge-base of `HEAD` and `--base`, so it fits a pull-request
check:

```sh
depward diff --lockfile --base origin/main --format markdown
```

Updated packages are diffed. New packages get the same registry and tarball checks as
`depward check`. A lockfile whose integrity hash disagrees with the registry is reported
as `lockfile-integrity-mismatch`.

Each package gets a risk: its highest finding severity, or `critical` when an update
has two `high` findings. The config applies here too. A `policy` override to `allow`
keeps a reviewed finding visible but out of the risk, the `allow` list does that for a
whole package, and a version on the `deny` list is always `critical`. Exit codes: `0`
below `--fail-on`, `20` when a package reaches it, `1` error, including a lookup that
failed (the report is still printed).

## `depward caps scan`

```
depward caps scan [options]

      --output <path>     Where to write (default capabilities.lock.json); "-" for stdout
      --json              Print the scan summary as JSON
      --concurrency <n>   Packages analyzed at once (default 8)
      --offline, --config   As for check
```

Writes `capabilities.lock.json`: for every registry package in the lockfiles of the
current directory, the capabilities static analysis finds (`fs`, `net`,
`child_process`, `env`, ...). Entries with capabilities are approved as `static`.
Run it again after you review a change: approvals of unchanged entries are kept, and
entries that are no longer locked are dropped. If any package can't be analyzed, nothing
is written and the exit code is `1`. Commit the file.

## `depward caps check` and `depward caps approve`

```
depward caps check [--format terminal|json|markdown|sarif] [--fail-on <level>] [--verbose]
depward caps approve <name>[@version]... [--cap <cap>]... [--reason <text>] [--by <name>]

      --caps-file <path>    The capability lockfile (default capabilities.lock.json)
      --concurrency, --offline, --config   As for scan
```

`check` is for CI. Every locked registry version is analyzed and compared with its
entry in `capabilities.lock.json`, or with the package's highest approved version when
the exact version has no entry. Each capability it uses that the entry doesn't list is a
`caps-unapproved` finding, and the exit code is `20`. The report uses the same formats
as `depward diff`, and the config's `policy`, `allow` and `deny` apply.

```sh
depward caps check --format markdown
depward caps approve some-package --reason "spawns its bundled binary"
```

`approve` analyzes the locked versions of a package (or the one version you name) and
records their capabilities with who approved them (`--by`, else `git config
user.name`), the date, and `--reason`. With `--cap`, only those capabilities are
approved on top of what the package already had.

`depward caps compare [--observed .depward/caps-observed.json]` checks what
`node --import @depward/caps/register` saw at runtime against the same file
(`caps-observed-unapproved`), with the same formats and exit codes as `check`. Runtime
observation is defense in depth, not a sandbox: see the
[caps README](../caps/README.md#limitations).

## Claude Code hook

Add this to `.claude/settings.json` (project) or `~/.claude/settings.json` (user):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "depward hook claude", "timeout": 10 }] }
    ]
  }
}
```

Install depward globally at a pinned version (`npm i -g depward@x.y.z`) rather than
running it through `npx`, which would itself be an unchecked install. Before Claude
runs a Bash command, depward reads it (never runs it) and checks every package it would
install or execute:

- **deny**: Claude is told why, with the suggested real package or older version.
- **ask**: you are asked to confirm, and Claude sees the reason too.
- **nothing to object to**: depward stays silent, and your normal permission rules
  apply. depward never auto-approves a command.

The check gives up after 4 s and then applies the config's `onError` (ask by default).
Logs go to stderr; stdout carries only the decision.

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
