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
  - An entry whose `name@version` and capabilities are unchanged keeps its existing
    `approvedBy`, `approvedAt` and `reason`.

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

## Runtime usage

```bash
node --import @depward/caps/register app.js         # mode from DEPWARD_CAPS_MODE=observe|enforce
DEPWARD_CAPS_MODE=observe node --import @depward/caps/register app.js
# writes .depward/caps-observed.json, which `depward caps compare` checks against the lockfile
```

In `enforce` mode, an unapproved use throws a `DepwardCapabilityError` that names the
package, the capability, and the call site.
