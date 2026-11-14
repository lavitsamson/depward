# 0007 — caps runtime: per-package builtins through `module.registerHooks`

- Status: accepted (2026-11-13; the `process.env` default was approved the same day)
- Date: 2026-11-13

## Context

Phase 4 runtime mode (M4.3 observe, M4.4 enforce) needs to know which package uses a
capability. `docs/specs/caps.md` § Runtime layer proposes redirecting builtin imports
through `module.registerHooks()` and asks five questions before building on it. The M4.0
spike answers them with a prototype in `spikes/m4.0-caps/` (throwaway; not published).

Docs checked 2026-11-13:
- <https://nodejs.org/api/module.html#moduleregisterhooksoptions>: added v22.15.0 /
  v23.5.0; Stability 1.2 (release candidate) since v24.13.1 / v25.4.0. `require()` and
  `require.resolve` of customized CJS modules always go through the hooks. Sync hooks are
  not inherited by worker threads unless registered from an `--import`/`--require` preload.
- <https://nodejs.org/api/util.html#utilgetcallsitesframecount-options>: Stability 1.1,
  added v22.9.0, renamed v22.12.0. Not affected by `Error.prepareStackTrace`; applies
  source maps when `--enable-source-maps` is on unless `sourceMap: false` is passed.

Tested on Windows 11 x64 with Node 22.23.2 and 24.21.0 (`node spikes/m4.0-caps/run-checks.mjs`
reproduces every answer below and exits 1 if one changes). Node 22.15.0 itself and
Linux/macOS were not run in the spike; the M4.3 test suite runs in the CI matrix.

### Prototype design

1. `resolve`: if the specifier (with or without `node:`) is a capability builtin
   (`MODULE_CAPS` in the analyzer, plus `fs/promises` and `dns/promises`) and
   `context.parentURL` is a file under `node_modules`, return
   `depward-cap:<module>?pkg=<name>&kind=cjs|esm`. `kind` is `cjs` when
   `context.conditions` contains `"require"`. The package name is the last
   `node_modules/<name>` (or `<@scope>/<name>`) segment of the parent URL.
2. `load`: for `depward-cap:` URLs return generated source. CJS:
   `module.exports = registry.moduleFor(name, pkg)`. ESM: `export default` that object
   plus one named export per key of the real module. The registry is a frozen object on a
   `Symbol.for` global, so the generated code needs no `require` of its own.
3. `moduleFor` returns a per-(module, package) **Proxy** of the real module. Its `get`
   trap wraps functions in a function Proxy (`apply` + `construct` traps) that counts the
   use and, in enforce mode, throws `DepwardCapabilityError`. Results are memoized per key
   and re-validated against the real value, so later monkey patches are seen. `promises`
   sub-objects are wrapped too, and wrappers are cached by real object, so
   `fs.promises === require("fs/promises")` still holds inside a package.
4. Globals: `fetch`, `process.getBuiltinModule` (not covered by the hooks) and
   `process.env` are replaced at startup with wrappers that attribute through a stack trace.

## Answers

**1. Does redirecting work for CJS `require` and ESM `import`? — Yes.**
CJS gets a working module object, including `fs.promises`; ESM default, named and
namespace imports work. `import()` from CJS and `createRequire(__filename)` inside a
package also go through the hooks. Each package gets its own object. Two side effects:
- On Node 24.21, `require.resolve("fs")` inside a package returns the `depward-cap:` URL
  (Node 22.23 returns `"fs"`). Both versions add `depward-cap:` keys to `require.cache`.
  Code that walks `require.cache` expecting file paths, or that calls
  `require.resolve(builtin)`, may break. M4.3 must test this on real packages.
- Enforcement runs at call time, not at import time. Importing a package that holds `fs`
  but never uses it is allowed.

**2. Does wrapping break `instanceof`, streams, or live bindings? — Mostly no, with two
limitations.**
- Works: `instanceof` against wrapped and real classes (the function Proxy forwards
  `.prototype`), `new`, `class X extends http.Server`, stream piping (the benchmark serves
  a file stream into an HTTP response), `util.promisify` including `promisify.custom`,
  function `name` and `length`, and graceful-fs style patches written through the wrapper
  (they reach the real module).
- **Identity:** `wrapped.Server !== http.Server`, and two packages get different `fs`
  objects. Code comparing builtin functions or classes with `===` across packages
  breaks. Passing classes through unwrapped would fix that, but then `new net.Socket()`
  would not be seen, so we keep wrapping them.
- **Live bindings:** ESM *named* imports are snapshots taken at link time, so they miss a
  later patch of the real module. Default and namespace access (`fs.readFileSync`) sees
  it. Node's own builtin ESM exports behave the same until the app calls
  `syncBuiltinESMExports()`, which the spike ignores. M4.3 can fix this by generating
  `export let` bindings and wrapping `syncBuiltinESMExports` to update them.
- **Wrapper leakage:** if a package stores one of *its* wrapped functions somewhere
  shared (in the real module, or in a closure that patches it, as graceful-fs does),
  later calls by any code count against that package. A `set`/`defineProperty` trap that
  unwraps known wrappers fixes the first case. Nothing can fix the closure case.

**3. Bundled dependencies — attributed to the bundle.** Attribution uses the importing
file's path, so code that a bundler inlined from another package is attributed to the
package that ships the bundle. Nested `node_modules` (`a/node_modules/b`) and pnpm's
`.pnpm/<id>/node_modules/<name>` resolve to the innermost package. Packages linked from a
workspace (realpath outside `node_modules`) count as application code and are not wrapped.
Yarn PnP zip paths are not supported. This matches the static layer, which profiles the
whole tarball including bundled code.

More generally, **attribution follows the importer of the builtin, not the caller**:
- A wrapper library holds the capability. Users of `fs-extra` do not show `fs`;
  `graceful-fs` does.
- A wrapped object handed to other code keeps its importer's identity.
- A real module object handed *into* a package by the app is unwrapped.

**4. Globals — stack attribution works but is expensive.** The first stack frame with a
location decides. If that frame is Node's own code (`node:internal/...`), nothing is
attributed. Without that rule, the module loader's read of
`process.env.WATCH_REPORT_DEPENDENCIES` was blamed on whichever package called `require`.
Calls made from timer callbacks are attributed correctly, because the callback is the
package's own code. A capture costs about **18 µs**. `getCallSites` costs the
same as `Error.captureStackTrace` but is immune to `prepareStackTrace` overrides (for
example source-map-support). It must be called with `sourceMap: false`, or source maps
can move a frame out of `node_modules`. Consequences:
- `fetch`, `WebSocket`, and the like: always attribute. A network call costs
  milliseconds, so the capture does not matter.
- `process.env`: attributing every read would cost about 18 µs per read, and
  some libraries read env in hot paths. The spike therefore attributes only
  credential-like keys (the analyzer's `env-sensitive-read` rule: TOKEN, SECRET, KEY,
  PASSWORD, `NPM_`/`AWS_`/`GITHUB_`/`GH_`/`CI_JOB`) plus enumeration (`ownKeys`, the
  exfiltration pattern). Ordinary reads such as `NODE_ENV` cost nothing extra.
  `DEPWARD_CAPS_ENV=all` attributes everything.
- If a package passes `fetch` as a callback into another package, the call is
  attributed to whoever's frame calls it.

**5. Overhead — within budget.** Requests are 2–3% slower, startup about 4 ms slower, and each wrapped call costs about 85 ns.

| Measure (median of 5 alternating rounds) | baseline | hooks | hooks + globals |
|---|---|---|---|
| Requests per second (fixture server) | 9,628 | 9,362 (−2.8%) | 9,431 (−2.0%) |
| Startup, loading all fixture packages | 647 ms | 651 ms | 651 ms |
| Wrapped trivial call (`os.endianness()`) | 1.1 ns | 85.6 ns | 86.8 ns |
| Wrapped syscall (`fs.statSync`) | 31.0 µs | 31.3 µs | 31.3 µs |
| Ordinary env read (`process.env.PATH`) | 5.3 µs | 5.2 µs | 12.7 µs |
| Credential-like env read (stack captured) | 0.3 µs | 0.3 µs | 18.3 µs |

"hooks" = builtins wrapped, globals off; "hooks + globals" = default spike configuration.
The request benchmark (`spikes/m4.0-caps/bench/server.mjs`) is an Express-like server
with an ORM-like client: 16 keep-alive connections across three routes (an ORM query via
`fs.promises` + `crypto`, a static file stream, and plain JSON). Timings on this machine
swing 2–3× under background load, so treat small differences as noise ("hooks +
globals" beating "hooks" is noise). Measured with Node 24.21.0 on win32-x64.

- A wrapped call costs one Proxy `get` trap (memoized; it was about 125 ns before the
  memo) plus one `apply` trap. M4.3 can replace the function Proxy with a plain closure
  for functions that are not constructors if this matters.
- An ordinary `process.env` read gets slower even though no stack is captured. On Windows
  *any* `get` trap on a Proxy over `process.env` makes a read about 2.4× slower (+7 µs),
  even an empty one; a Proxy without a `get` trap costs nothing. Env reads are an OS
  lookup on Windows (about 5 µs) and probably far cheaper on Linux; not measured. If this
  matters, M4.3 can serve reads from a snapshot object with write-through to the real env
  (risk: changes made natively, such as `process.loadEnvFile`, would be missed).

### Bypasses (the runtime layer is defense in depth, not a sandbox)

Confirmed in the spike to reach the real `fs`:
- `Module._load("fs", null)`.
- `process.mainModule.require("fs")`: attributed to the app, which is unwrapped.
- `process.binding("fs")`: deprecated, but it still returns the raw binding.

Not probed, but bypasses by construction:
- Native addons.
- Real module objects that the app passes in.
- Child processes that don't inherit `--import`.
- Tampering with the intrinsics the wrappers use. A package can replace `Reflect.apply`
  or `WeakMap.prototype.get`; the real implementation must capture these at startup.

Methods on instances (`socket.write`, `server.listen`, a `FileHandle`'s methods) are not
wrapped. Only the module-level functions and constructors that produce those instances
are.

## Decision

- The `registerHooks` approach is **feasible**. The `diagnostics_channel` fallback from
  the spec is not needed.
- M4.3/M4.4 build `@depward/caps/register` on the prototype design above, rewritten in
  TypeScript with tests, plus these changes:
  - Capture intrinsics at startup.
  - Skip the caps package's own install directory instead of a single file.
  - Use `util.getCallSites({ sourceMap: false })` for stack attribution.
  - Wrap `WebSocket`, `XMLHttpRequest`, and `EventSource` like `fetch`.
  - Unwrap known wrappers in a `set` trap.
  - Generate live ESM bindings that follow `syncBuiltinESMExports`.
- Builtins are mapped to capabilities with the analyzer's `MODULE_CAPS` table, so the
  static and runtime layers share capability names.
- `process.env` attribution defaults to credential-like keys plus enumeration (needs a
  spec edit; see Consequences).
- The Node floor stays at 22.15. The M4.3 CI matrix adds a job on exactly 22.15.0, which
  the spike did not run.

## Consequences

- Runtime attribution is per installed package path. Bundled code, wrapper libraries and
  objects handed across packages blur it. The docs and the `observe` report must say so,
  and the README must say *not a sandbox*, per the spec's honesty requirement.
- Wrapped builtins break `===` identity across packages and leave ESM named imports
  without live bindings until the M4.3 fix. On Node 24, `require.resolve` of a builtin
  inside a package returns a `depward-cap:` URL. Any of these can break a real
  application. Enforce mode should stay opt-in, and observe mode must first be tried on
  real apps (DoD: the Express + Prisma-like fixture).
- `registerHooks` is a release candidate (1.2), not stable. `getCallSites` is 1.1. An API
  change in Node can break the runtime layer; CI covers Node 22 and 24.
- Spec edit (done, `docs/specs/caps.md` § Runtime details): `process.env` stack
  attribution applies only to credential-like keys and enumeration by default.

## Implementation notes (M4.3, 2026-11-13)

`packages/caps/src/runtime/` implements the decision above. The follow-ups listed under
Decision are done: captured intrinsics, live ESM bindings through
`syncBuiltinESMExports`, unwrapping in `set`/`defineProperty`, `getCallSites` with
`sourceMap: false`, and `WebSocket`/`EventSource`. Lessons from building it:

- The "self" root is the directory of the register file (`src/runtime/` or `dist/`),
  not the package root. Otherwise an app inside the package (the test fixtures) is never
  attributed. The same bug showed up in the spike.
- Own function-valued properties of wrapped functions are wrapped too
  (`fs.realpathSync.native`). Properties Node defines as non-configurable and
  non-writable (`fs.exists[util.promisify.custom]`) can't be: a Proxy must return them
  unchanged, so `util.promisify(fs.exists)` calls go uncounted.
- The generated modules reach the runtime through a frozen global registry. A package
  can call it directly and get another package's wrapper. That is one more bypass,
  consistent with "not a sandbox".
- Measured on the fixture server: 1.9% request overhead, and +16 ms startup from `dist/`
  (`docs/benchmarks.md` § Phase 4).

## Enforce mode (M4.4, 2026-11-13)

Enforce mode reuses the observe machinery. Each use record gets an `allowed` flag,
decided once per (package, capability) from `capabilities.lock.json` (the same reference
rule as `caps check`), so approved calls cost the same as in observe mode. A denial
captures the call site and throws `DepwardCapabilityError` before the real function runs.
The policy fails closed at startup.

Enforcement can see uses static analysis misses. So `caps approve --cap` now accepts any
known capability, and a re-scan keeps approvals that cover the detected set
(`docs/specs/caps.md` § Enforce details). Request overhead measured within noise of
observe mode (`docs/benchmarks.md` § Phase 4).
