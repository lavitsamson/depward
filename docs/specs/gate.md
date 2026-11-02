# Spec: @depward/gate (+ CLI, agent hooks, MCP)

Answers one question before anything is installed: **should this package (or command)
be allowed?** The result is `allow`, `ask`, or `deny`, plus readable reasons.

## Flow

```
input (package specs | shell command)
  → tokenize command → list of PackageRequest {name, range, source, via: "install"|"exec"}
  → resolve range → version (packument)
  → registry checks          (fast, metadata only)
  → tarball checks           (analyzer; skipped if a registry check already says deny)
  → update path? → diff vs lockfile version (Phase 3, M3.6)
  → policy engine → Decision {action, findings[], perPackage[]}
```

## Command tokenizer

Write a small POSIX-ish shell tokenizer that handles quotes, escapes, `&&`, `||`, `;`,
`|`, subshell parentheses, and `env VAR=x` prefixes. Do not evaluate anything. Recognize:

| Tool | Install forms | Exec forms |
|---|---|---|
| npm | `install`, `i`, `add`, `isntall` (typo alias), `ci` (lockfile mode) | `exec`, `npx`, `init <x>` (maps to `create-x`) |
| pnpm | `add`, `install <pkg>`, `i <pkg>` | `dlx`, `create` |
| yarn | `add`, `global add` | `dlx`, `create` |
| bun | `add`, `install <pkg>`, `i <pkg>` | `bunx`, `x`, `create` |

Specs to handle:
- `name`, `name@range`, `@scope/name@tag`
- `alias@npm:real@range`. Check the *real* package
- git, GitHub shorthand, URL, and `file:` specs. These produce a `non-registry-source`
  finding (default: ask)

Ignore flags but preserve them. `-g` and `--global` add an `info` note.

If a command clearly involves a package manager but can't be parsed, produce an
`unparseable-command` finding (default: ask). Commands with no package-manager
invocation produce an `allow` with no findings and must return within 50 ms.

Lockfile-mode commands (`npm ci`, `pnpm install` with no args): `allow`. Lockfile
changes are diff's job.

## Registry checks

| Finding ID | Default | Logic |
|---|---|---|
| `package-not-found` | deny | packument returns 404. Message says it may be AI-hallucinated or a typo |
| `known-hallucinated-name` | deny | name is in `data/hallucinated-names.json` (even if it now exists) |
| `version-not-found` | deny | no version satisfies the range or tag |
| `version-too-new` | ask | resolved version is younger than `minVersionAgeDays` (7). Suggest the newest version that is old enough |
| `package-too-new` | ask | first publish is younger than `minPackageAgeDays` (30) |
| `low-downloads` | ask | weekly downloads below `minWeeklyDownloads` (500). Combined with `package-too-new` → deny |
| `typosquat-suspect` | ask | Levenshtein ≤ 2 (or ≤ 1 for names of 5 chars or fewer), or a separator/scope swap, against `data/popular-packages.json`, and this package is much less popular |
| `publisher-changed` | ask | `_npmUser` of the resolved version is not among the publishers of the previous 5 versions |
| `maintainer-added-recently` | low | the maintainers list changed in the last 30 days (compare against older versions) |
| `provenance-dropped` | high (ask) | earlier versions had attestations, this one doesn't |
| `deprecated` | low | `deprecated` field is set |
| `non-registry-source` | ask | from the tokenizer |

## Tarball checks

Run the analyzer and map its signals to findings one-to-one. Escalations:
- `install-script` together with `package-too-new` or `low-downloads` → deny
- any `critical` signal → deny

## Policy engine

- Start from the default action per finding ID. Apply config overrides, then the
  `allow`/`deny` lists (glob matching on names, exact matching on `name@version`).
- Package decision = the most severe action among its findings.
- Command decision = the most severe action among its packages.
- `onError` (network failure, timeout) defaults to **ask**, never silent allow.
  `DEPWARD_OFFLINE=1` runs only cached and offline checks.

## CLI (`depward`)

```
depward check <spec...>                 # e.g. depward check left-pad@1.3.0 @scope/x
depward check --command "<shell cmd>"   # tokenize first
depward hook claude                     # reads hook JSON on stdin, writes decision JSON
depward diff ...                        # Phase 3
depward caps ...                        # Phase 4
Common: --json  --format terminal|json|markdown|sarif  --config <path>  --offline  --verbose
Exit codes: 0 allow · 10 ask · 20 deny · 1 internal error
```

## Claude Code hook adapter

**Before implementing, read the current Claude Code hooks documentation**
(docs.claude.com → Claude Code → Hooks). Confirm the stdin payload shape and the
PreToolUse decision output format, and cite the URL in a comment.

Expected design (verify):
- Register on `PreToolUse` with matcher `Bash`. Read `tool_input.command` from stdin JSON.
- Map the decision `allow`/`ask`/`deny` to the hook's permission decision. Put a
  concise, model-readable reason in the decision reason field, for example:
  `"depward: deny react-codeshift — package-not-found (may be hallucinated). Did you mean jscodeshift?"`
  The reason should help the agent self-correct: include the suggested real name or the
  older safe version.
- Total time budget: 4 s. On timeout, use `onError`. This is deliberately below the 5 s
  cold-check target: a cold-cache check may time out and fall back to `onError` (`ask`
  by default). That is accepted; a warm cache stays well inside the budget.
- Never write anything to stdout other than the decision JSON. Send logs to stderr.

Setup docs should recommend a **pinned global install** (`npm i -g depward@x.y.z`) over
`npx depward` in the hook, because `npx` would itself be an unchecked install.

Later adapters (behind an `Adapter` interface, `src/adapters/*`): Cursor, Codex CLI, and
a generic `--stdin-command` mode. Add each one only after checking that tool's current
hook docs.

## MCP server (`@depward/mcp`)

Use the official TypeScript MCP SDK (check the current API). Transport: stdio.

Tools:
- `check_packages({ specs: string[] })` → decision plus findings
- `check_install_command({ command: string })` → decision plus findings
- `diff_versions({ name, from, to })` (Phase 3)

Tool descriptions should tell the agent to call `check_install_command` *before* running
any install, and to prefer suggested alternatives when the result is `deny`.

## Data files

- `data/popular-packages.json`: about 10,000 names with weekly download counts. It is
  regenerated by `scripts/update-popular.ts`. Choose and document the data source in an
  ADR during M2.9. Record the snapshot date in the file.
- `data/hallucinated-names.json`: `{name, ecosystem, firstSeen, source, suggestion}`.
  Seed it only with publicly documented cases, citing each source URL, plus a
  contribution process in CONTRIBUTING.md.

## Tests

- Tokenizer: table-driven, at least 80 cases, including adversarial quoting and chained
  commands.
- Each finding: a recorded-fixture registry with positive and negative cases.
- Hook: golden stdin → stdout JSON files.
- Benchmark script `scripts/bench-gate.ts` for warm and cold latency.
- Live: top-1,000 false-positive run (`pnpm test:live -- gate-fp`). Writes results to
  `docs/benchmarks.md`.
