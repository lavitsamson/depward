# Spec: @depward/caps (Phase 4)

Per-package least privilege for Node.js. It has two layers:

1. **Static (CI):** a capability lockfile that fails the build when an update grants a
   dependency a capability it never had before.
2. **Runtime (optional):** attributes uses of builtin modules to the package that made
   them, in `observe` or `enforce` mode.

**Honesty requirement:** document prominently that runtime mode is *defense in depth,
not a sandbox*. Same-process code can bypass it, for example through `process.binding`,
prototype tampering, or native addons. Never market it as isolation.

## Static layer

`capabilities.lock.json`:
```json
{
  "version": 1,
  "packages": {
    "express@5.1.0": { "capabilities": ["fs", "net"], "approvedBy": "static", "approvedAt": "2026-11-02" },
    "left-pad@1.3.0": { "capabilities": [] }
  }
}
```
- `depward caps scan` creates the file from the current lockfile and analyzer profiles.
- `depward caps check` (CI): for every lockfile entry, compute its capabilities and
  compare them with the most recent approved entry for that package name. Capabilities
  that are new and not approved → fail. Uses the same report formats as diff.
- `depward caps approve <name>[@version] [--cap net]` records an approval with an
  optional `reason`.

### Scan details (M4.1 clarifications)

- **Input:** every known lockfile in the working directory (the same list as
  `depward diff --lockfile`). Entries from several lockfiles are merged by `name@version`.
- **Capabilities** are the analyzer's capability names (`fs`, `net`, `child_process`,
  `env`, `dynamic_code`, `native_addon`, `worker`, `dynamic_require`, `crypto`,
  `os_info`) with at least one recorded use in the version's profile, sorted
  alphabetically. The runtime layer uses the same names (ADR 0007).
- **Registry entries only.** `workspace`, `link` and `file` entries are first-party
  code. `bundled` entries are already part of their parent's tarball profile. `git`,
  `tarball` and `other` entries can't be fetched from the registry. None of them get an
  entry; the scan reports them as skipped, and `caps check` (M4.2) reports the
  unverifiable sources.
- **Approval fields:** an entry with at least one capability gets
  `"approvedBy": "static"` and `"approvedAt": "<YYYY-MM-DD, UTC>"`. An entry with no
  capabilities has only `"capabilities": []`, as in the example above. An optional
  `"reason"` string is kept as written (`caps approve` sets it).
- **Re-scan = re-baseline.** Running `scan` again approves what is locked now:
  - Entries no longer in any lockfile are dropped.
  - New entries are approved as `static`.
  - An entry whose approvals cover every detected capability keeps its existing
    `capabilities`, `approvedBy`, `approvedAt` and `reason`. That includes approvals of
    capabilities static analysis doesn't see (amended in M4.4).
  - Otherwise the entry is re-approved as `static`, with the detected capabilities plus
    the previously approved ones.

  CI runs `check`, never `scan`.
- **All or nothing.** If any registry entry can't be analyzed, the scan exits 1 and
  writes nothing, so a baseline never silently lacks a package. Causes: network error,
  missing version, unsafe tarball, a tarball that doesn't match the registry's
  integrity, or a lockfile integrity that disagrees with the registry.
- **Limits:** at most 5,000 registry entries by default (`LIMIT_EXCEEDED`), analyzed 8
  at a time through the gate's tarball check and its analysis cache (ADR 0005).
- **Format:**
  - Packages are sorted by name, then by semver version.
  - Fields are written in the order `capabilities`, `approvedBy`, `approvedAt`,
    `reason`.
  - The file is 2-space indented JSON with a trailing newline.
  - Unknown top-level or entry fields are an error (`INVALID_LOCKFILE`), as is any
    `version` other than 1.

```bash
depward caps scan [--output capabilities.lock.json | --output -] [--json] [--offline]
```

### Check details (M4.2 clarifications)

- **Input:** the same lockfiles as `scan`, plus the capability lockfile (`--caps-file`,
  default `capabilities.lock.json`). A missing capability lockfile is an error: run
  `scan` first.
- **Reference entry:** the exact `name@version` entry if there is one; otherwise the
  entry of the same name with the highest version (the "most recent approved entry").
  A name with no entry at all has no approvals.
- **`caps-unapproved`:** one finding per capability that the locked version uses and the
  reference entry does not list. Severity is medium, or high for `child_process`,
  `dynamic_code` and `native_addon` (the same split as `diff-new-capability`). The
  evidence is the version's uses, up to 10.
- **Also reported, with diff's finding IDs:**
  - `non-registry-source` for `git`, `tarball` and `other` entries (not `workspace`,
    `link`, `file`, `bundled`).
  - `lockfile-integrity-mismatch`, `tarball-integrity-mismatch`, and `tarball-unsafe`.
- **Failures:** network failures and missing versions are errors, not findings.
- **Report:** the diff report (terminal, JSON, Markdown, SARIF). Only packages with
  findings or errors appear.
  - `kind` is `updated` (`from` = the reference entry's version, which equals `to` for
    an exact entry) or `added` (no entry for the name).
  - The config's `policy`, `allow` and `deny` apply as in `diff`.
  - Entries of the capability lockfile that are no longer locked are ignored (`scan`
    prunes them).
- **Exit codes:**
  - `20` when a `caps-unapproved` finding counts (is not allowed by the config), or when
    a package's risk reaches `--fail-on` (default `critical`).
  - Otherwise `1` when a package could not be checked.
  - Otherwise `0`.

### Approve details (M4.2 clarifications)

```bash
depward caps approve <name>[@version]... [--cap <cap>]... [--reason <text>] [--by <who>]
```

- **Targets:** with a version, that version, which must be locked. Without one, every
  locked registry version of the name. Nothing locked is an error.
- **What gets approved:** each target is analyzed.
  - Without `--cap`, all of its capabilities are approved.
  - With `--cap`, the approved set is the reference entry's capabilities that the version
    still uses, plus the named ones. A named capability doesn't have to be detected
    statically, because runtime enforcement can see uses static analysis misses (amended
    in M4.4). An unknown capability name is an error, which catches typos.
- **Recorded fields:**
  - `approvedBy` is `--by`, else `git config user.name`, else `manual`.
  - `approvedAt` is today's date (UTC).
  - `reason` is `--reason`.
- The capability lockfile is created if it doesn't exist. Other entries are not touched.

## Runtime layer — spike first (M4.0)

Hypothesis: with `module.registerHooks()` (synchronous, applies to both `require` and
`import`), the `resolve` hook sees `context.parentURL`. That lets us find which package
is importing a builtin. We can then redirect `node:fs` → `depward-cap:fs?pkg=<name>`,
and the `load` hook returns a wrapper module that checks policy and then re-exports the
real builtin.

The spike must answer these questions and record the answers in an ADR:
1. Does redirecting a builtin to a custom URL scheme work for both CJS `require` and ESM
   `import`? Does CJS still get a working module object, including named exports such as
   `fs.promises`?
2. Can we wrap the builtin without breaking `instanceof`, streams, and live bindings?
3. How does it behave with bundled dependencies, where one package contains another
   package's code? Attribution is per-package path, so document that limitation.
4. Globals (`fetch`, `WebSocket`, `process.env`): use stack-trace attribution through a
   wrapper installed at startup. What does it cost, and how reliable is it?
5. Overhead at startup and per call, measured on a small Express-like fixture app.

If the answer to (1) is no, fall back to observe-only via `diagnostics_channel` and
`async_hooks`, and report to the user before continuing.

**Result:** feasible. See `docs/adr/0007-caps-runtime-hooks.md` (accepted) for the
answers and the design.

### Runtime details (M4.3 clarifications)

- **Builtins → capabilities:**
  - `fs` and `fs/promises` → `fs`.
  - `http`, `https`, `http2`, `net`, `tls`, `dgram`, `dns` and `dns/promises` → `net`.
  - `child_process` → `child_process`.
  - `vm` → `dynamic_code`.
  - `worker_threads` and `cluster` → `worker`.
  - `crypto` → `crypto`.
  - `os` → `os_info`.

  Importing is free; each call of a function or constructor from the module counts as
  one use.
- **Globals (stack attribution):**
  - `fetch`, `WebSocket` and `EventSource` → `net`.
  - `process.getBuiltinModule` → the builtin's capability.
  - `process.dlopen` → `native_addon`.
  - `process.env` → `env`. By default only reads of credential-like keys (the analyzer's
    `env-sensitive-read` rule: TOKEN, SECRET, KEY, PASSWORD, `NPM_`, `AWS_`, `GITHUB_`,
    `GH_`, `CI_JOB`) and enumeration of the whole environment are attributed, because
    each capture costs about 18 µs (approved 2026-11-13). `DEPWARD_CAPS_ENV=all`
    attributes every read.
- **Not observed:** `eval`, `new Function`, `dynamic_require`.
- **Attribution:** the package is the innermost `node_modules/<name>` (or
  `<@scope>/<name>`) segment of the importing file (builtins) or of the first stack
  frame with a location (globals). Its version comes from that directory's
  `package.json`, so the key is `name@version`, as in the capability lockfile.
  Application code is not attributed.
- **Output:** `observe` mode writes `.depward/caps-observed.json` (relative to the
  working directory at startup; `DEPWARD_CAPS_OUT` overrides) when the process exits. An
  existing file is merged (counts add up, members are unioned), so several runs (a test
  suite, then the app) accumulate. Format:
  ```json
  { "version": 1, "packages": { "orm-client@1.0.0": { "fs": { "count": 3, "members": ["fs.readFileSync"] } } } }
  ```
  Members are capped at 50 per capability. Nothing is written when nothing was observed.
  A process killed by a signal writes nothing.
- **Scope:**
  - Worker threads are not observed. The hooks are not installed in workers in M4.3.
  - Child processes are observed only if they get the `--import` flag themselves (for
    example through `NODE_OPTIONS`).
- **`depward caps compare`** reads the observed file and the capability lockfile and
  reports `caps-observed-unapproved`: one finding per observed capability that the
  package's reference entry (same rule as `check`) doesn't list. It uses the same report
  formats and exit codes as `check`.
- `DEPWARD_CAPS_MODE` is `observe` (the default) or `enforce`. Any other value prints a
  warning and observes.

### Enforce details (M4.4 clarifications)

- **Policy:** `capabilities.lock.json` in the working directory at startup
  (`DEPWARD_CAPS_LOCKFILE` overrides). A package may use a capability when its reference
  entry lists it. The reference rule is the same as `check`: the exact `name@version`,
  else the highest version of that name. A package with no entry may use nothing.
- **Fails closed:** a missing or invalid capability lockfile throws
  `DepwardCapabilityError` (`code: "CAPS_POLICY"`) at startup, so the application never
  runs unprotected by accident.
- **Denial:** an unapproved use throws `DepwardCapabilityError` with
  `code: "CAPS_DENIED"` and `denied: { package, capability, member, callSite }`. The
  message names all four and suggests `depward caps approve <name> --cap <cap>`. The
  real function is not called.
  - The decision is made once per (package, capability), so approved calls cost the
    same as in observe mode.
  - Importing is never denied, and application code is never restricted.
- **Same coverage as observe mode:** the globals, the env rule, and the limitations of
  § Runtime details apply. Observations are still written.
- **A package can catch the error itself** (for example around an optional feature).
  The use is still prevented, but nothing is reported unless the observed file is
  checked.
- **Approving what static analysis misses:** `caps approve --cap <cap>` accepts any known
  capability name, even one static analysis doesn't see in the version, so a runtime-only
  use can be approved. A re-scan keeps an entry whose approvals cover every detected
  capability.

## Runtime usage

```bash
node --import @depward/caps/register app.js         # mode from DEPWARD_CAPS_MODE=observe|enforce
DEPWARD_CAPS_MODE=observe node --import @depward/caps/register app.js
# writes .depward/caps-observed.json, which `depward caps compare` checks against the lockfile
```

In `enforce` mode, an unapproved use throws a `DepwardCapabilityError` that names the
package, the capability, and the call site.
