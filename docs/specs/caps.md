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
