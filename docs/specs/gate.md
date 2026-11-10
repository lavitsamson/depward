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
- `workspace:` specs refer to packages inside the user's own monorepo. They produce a
  `PackageRequest` with `source: "workspace"` but no finding, and registry checks skip
  them

Ignore flags but preserve them. `-g` and `--global` add an `info` note.

If a command clearly involves a package manager but can't be parsed, produce an
`unparseable-command` finding (default: ask). A shell syntax error (for example an
unclosed quote) produces only that one finding: no partial `PackageRequest`s are
extracted from the broken command. Commands with no package-manager invocation produce
an `allow` with no findings and must return within 50 ms.

`npm update` / `pnpm update` / `yarn upgrade` are not install forms. They move existing
dependencies within their declared ranges, and the resulting lockfile change is diff's
job (like lockfile-mode commands below).

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
| `typosquat-suspect` | ask | Edit distance ≤ 2 (or ≤ 1 for names of 5 chars or fewer; optimal string alignment, so swapping two adjacent letters counts as 1), or a separator/scope swap, against `data/popular-packages.json`, and this package is much less popular |
| `publisher-changed` | ask | `_npmUser` of the resolved version is not among the publishers of the previous 5 versions, and is not an established maintainer (listed on the previous version and on the newest version published 30+ days earlier) |
| `maintainer-added-recently` | low | the maintainers list changed in the last 30 days (compare against older versions) |
| `provenance-dropped` | high (ask) | earlier versions had attestations, this one doesn't |
| `deprecated` | low | `deprecated` field is set |
| `non-registry-source` | ask | from the tokenizer |

How M2.2 reads the table (`checkRegistry`, `src/registry/`):
- Severities: `known-hallucinated-name` critical; `package-not-found`,
  `version-not-found`, `typosquat-suspect`, `provenance-dropped` high;
  `version-too-new`, `package-too-new`, `low-downloads`, `publisher-changed` medium;
  `maintainer-added-recently`, `deprecated` low. Actions come from the policy engine's
  per-ID defaults in the table above, not from severity. The engine (M2.4) also owns
  every escalation (`low-downloads` + `package-too-new` → deny).
- Range resolution follows npm (npm-pick-manifest): a dist-tag names its version;
  for a range, `latest` wins when it satisfies, otherwise the highest satisfying
  version, preferring non-deprecated ones. `resolveVersion` lives in `@depward/core`
  (the only package allowed to use `semver`).
- The suggested version for `version-too-new` is the newest old-enough version within
  the requested range, else the newest old-enough version overall (labelled "outside
  the requested range").
- "Previous versions" means earlier by publish time, not by semver. `publisher-changed`
  and `provenance-dropped` look at the previous 5. For a stable version,
  `provenance-dropped` counts only earlier stable versions (approved 2026-11-10, after
  rxjs@7.8.2 was flagged because of its attested 8.0 alphas); a prerelease counts all.
- Approved changes (2026-11-10), made after the live run:
  - `publisher-changed` exempts established maintainers. typescript@7.0.2 was flagged
    only because its CI account, listed for months, had not published in the last 5
    versions. "Established" also needs a listing 30+ days earlier. Without that, an
    attacker could list a new account in one release and publish from it in the next.
  - Typosquat distance is optimal string alignment (OSA) rather than plain
    Levenshtein. Swapped letters are a common typo, and short names (limit 1) missed
    them (`axois`, `raect`).
- `maintainer-added-recently` compares per-version `maintainers` of versions published
  in the last 30 days with the newest version older than that. It is package-level
  (no `version`), and it is skipped when no version is older than 30 days.
- `typosquat-suspect`: "much less popular" means the popular package has ≥ 100× the
  weekly downloads (unknown counts count as 0). The ≤ 1 limit applies when the *popular*
  name has 5 characters or fewer. Names on the popular list are never flagged, and names
  in the same scope are never compared (only the scope owner can publish there).
- `package-not-found` suggests the closest popular name, if any is within the typosquat
  limits. Every finding run also fills `suggestion.{name,version}` for the hook reason.
- `known-hallucinated-name` does not short-circuit: the registry checks still run, so
  a config that allows the name still gets the other findings.
- Failed lookups never throw: they are returned in `errors[]` next to any findings
  already made, and the policy engine applies `onError`.
- The data files ship in `@depward/gate` as `dist/data/*.json`, separate from the
  bundle (the popular list is CC BY-SA 4.0; ADR 0003). `RegistryCheckOptions.data`
  overrides them.

## Tarball checks

Run the analyzer and map its signals to findings one-to-one. Escalations:
- `install-script` together with `package-too-new` or `low-downloads` → deny
- any `critical` signal → deny

Archive failures are findings, not errors (approved 2026-11-10), so a crafted archive
can't downgrade itself to `onError`:

| Finding ID | Default | Logic |
|---|---|---|
| `tarball-integrity-mismatch` | deny (critical) | the bytes don't match `dist.integrity` / `dist.shasum`, or there is no usable hash |
| `tarball-unsafe` | deny (high) | unsafe entry paths or links, corrupt archive, no `package.json` object, or over a size or entry limit |

Network failures and timeouts while downloading stay errors (`onError`).

How M2.3 reads this (`checkTarball`, `checkPackage`):
- Findings are reported under the requested name and version, never the archive's own
  `package.json`.
- `checkPackage` runs the tarball stage whenever a version resolved. Skipping it once a
  registry finding already denies needs the policy engine's actions, so M2.4 adds that.
- The escalations above are applied by the policy engine (M2.4), like the registry ones.

## Policy engine

- Start from the default action per finding ID. Apply config overrides, then the
  `allow`/`deny` lists (glob matching on names, exact matching on `name@version`).
- Package decision = the most severe action among its findings.
- Command decision = the most severe action among its packages.
- `onError` (network failure, timeout) defaults to **ask**, never silent allow.
  `DEPWARD_OFFLINE=1` runs only cached and offline checks.

How M2.4 reads this (`createPolicy`, `checkSpecs`, `checkCommand`; `src/policy/`):
- Analyzer signals (approved 2026-11-10) default by severity: critical → deny, high →
  ask, lower → allow. The exception is `env-sensitive-read` → allow: it still fires on
  benign environment enumeration (next, debug, esbuild), and the stealer shape is
  `env-exfil-pattern`, which denies. `install-script` is allowed alone and denied by
  the escalation. An ID with no default (a future one) falls back to the same
  severity mapping. Every default is listed in `docs/findings.md`.
- Order per finding: default → escalations → the config's `policy` override → lists.
  An explicit `policy` override beats an escalation, because it is the project's own
  choice. Escalations look only at the same package's findings. "Any critical → deny"
  applies to every critical finding, not only analyzer signals.
- Lists: `deny` wins over `allow`. In a name glob, `*` and `?` stay within one
  segment (`@myorg/*` never matches `@myorg-evil/x`), and `**` crosses `/`. Versions
  match exactly, as strings: no ranges. Malformed entries are `INVALID_CONFIG`.
  - An allow-listed package: every finding becomes allow (kept for the report), and
    `onError` doesn't apply. The registry checks still run (cheap, and they resolve the
    version for `name@version` entries). The tarball is skipped.
  - A deny-listed package gets a `denylisted` finding (deny, not overridable), so
    reports always say why. A name-only deny entry skips every lookup.
- The tarball is skipped whenever the registry stage already decides the outcome:
  the package is denied, or allow-listed.
- `Decision` = `{ action, packages: PackageDecision[], findings, reasons }`. Tokenizer
  findings attach to the package they name. The rest (`unparseable-command`) are
  command-level `findings`. `reasons` has one line per non-allow cause, deny first,
  for the hook's reason text. Duplicate requests (same source, name, range) are
  checked once. Workspace and non-registry requests are never looked up.
- `DEPWARD_OFFLINE=1` is implemented in core's registry client (`offline` option): it
  serves cached data at any age, and uncached data fails with `OFFLINE`, which costs
  `onError`. Checks that need no network (the hallucinated-name list) still deny.

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
