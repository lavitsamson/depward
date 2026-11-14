# @depward/caps

Per-package least privilege for npm dependencies. It writes a capability lockfile,
`capabilities.lock.json`, that records what each locked package can do according to
static analysis (`fs`, `net`, `child_process`, `env`, ...). Package code is never run:
tarballs are fetched, checked against their integrity hash, and analyzed in memory.

> **Status:** Phase 4 complete: the static layer (`depward caps scan|check|approve`),
> runtime observe mode (`@depward/caps/register`, `depward caps compare`), and enforce
> mode (`DEPWARD_CAPS_MODE=enforce`). See the
> [roadmap](../../docs/ROADMAP.md) and [spec](../../docs/specs/caps.md).

## Example

```js
import { readFile, writeFile } from "node:fs/promises";
import { createRegistryClient } from "@depward/core";
import { CAPS_LOCKFILE_NAME, parseCapsLockfile, scanCapabilities, serializeCapsLockfile } from "@depward/caps";

const existing = await readFile(CAPS_LOCKFILE_NAME, "utf8").then(parseCapsLockfile, () => null);
const result = await scanCapabilities({ cwd: process.cwd(), registry: createRegistryClient(), existing });

if (result.errors.length > 0) {
  for (const e of result.errors) console.error(e.code, e.message);
  process.exit(1);
}
await writeFile(CAPS_LOCKFILE_NAME, serializeCapsLockfile(result.lockfile));
console.log(`${result.counts.scanned} packages, ${result.counts.withCapabilities} with capabilities`);
```

The same thing from the command line:

```sh
depward caps scan
```

```json
{
  "version": 1,
  "packages": {
    "express@5.1.0": { "capabilities": ["fs", "net"], "approvedBy": "static", "approvedAt": "2026-11-02" },
    "left-pad@1.3.0": { "capabilities": [] }
  }
}
```

A re-scan is a re-baseline: it approves what is locked now. Approvals of entries whose
capabilities are unchanged are kept, and entries that are no longer locked are dropped.
In CI, `depward caps check` (or `checkCapabilities`) fails when a locked version uses
a capability its entry doesn't list (`caps-unapproved`); `depward caps approve <name>`
records the approval. Only registry packages are listed. Workspace, link, file, bundled, git and tarball-URL
entries are reported as skipped.

## Runtime observe mode

> **This is defense in depth, not a sandbox.** It attributes what packages do inside
> your process; it does not isolate them. Code in the same process can bypass it (see
> the limitations below). Never rely on it as a security boundary.

```sh
node --import @depward/caps/register app.js      # writes .depward/caps-observed.json on exit
depward caps compare                             # observed use vs capabilities.lock.json
```

Each capability builtin (`fs`, `http`, `child_process`, `vm`, `worker_threads`,
`crypto`, `os`, ...) that a package imports is replaced, for that package only, by a
wrapper that counts calls under the package's `name@version`. `fetch`, `WebSocket`,
`process.getBuiltinModule`, `process.dlopen` and `process.env` are attributed through
the call stack. Only credential-like env keys and enumeration of the whole environment
are attributed, unless `DEPWARD_CAPS_ENV=all`. Runs accumulate in the observed file
(`DEPWARD_CAPS_OUT` moves it). Overhead on a request benchmark is about 2%
(`docs/benchmarks.md`).

### Enforce mode

```sh
DEPWARD_CAPS_MODE=enforce node --import @depward/caps/register app.js
```

- A package's use of a capability that `capabilities.lock.json` doesn't approve throws
  `DepwardCapabilityError` (`code: "CAPS_DENIED"`). Its `denied` property names the
  package, the capability, the member (`fs.readFileSync`) and the call site, and the
  real function is not called.
- Approval uses the same reference rule as `caps check`: the exact version's entry, else
  the package's highest approved version. A package with no entry may use nothing.
- Importing is never denied, and application code is never restricted.
- A missing or invalid capability lockfile stops the process at startup
  (`code: "CAPS_POLICY"`). `DEPWARD_CAPS_LOCKFILE` points at another file.
- Approved calls cost the same as in observe mode.
- To allow a use static analysis didn't detect, run
  `depward caps approve <name> --cap <cap> --reason "..."`.

Everything under the limitations below applies to enforce mode too. In particular, a
package can bypass it, and a package can catch the error itself. Treat a denial as a
strong signal, not a guarantee.

### Limitations

- **Bypasses:**
  - `Module._load`, `process.mainModule.require` and `process.binding` reach the real
    builtins.
  - So do native addons, and real module objects that the application passes to a
    package.
  - A package can also call the runtime's global registry directly, and attribute use
    to another package.
  - A package can register its own `module.registerHooks` resolve hook, which runs
    before the runtime's and can hand it the real builtins.
  - Worker threads run without the runtime, so a package approved for `worker` can do
    anything in a worker.
  - Replacing JavaScript built-ins (`Set.prototype.has`, `String.prototype.*`,
    `JSON.parse`, `URL`, the array iterator, ...) is covered: the runtime captures what
    it uses at startup, and tests probe each of these.
- **Attribution follows the importer, not the caller:**
  - A wrapper library (`graceful-fs`, `fs-extra`) is blamed for its callers' use.
  - Code a bundler inlined into a package counts as that package.
  - A wrapped object handed to other code keeps its importer's identity.
  - Workspace and `file:` packages (real path outside `node_modules`) count as
    application code.
  - Yarn Plug'n'Play is not supported.
- **Not observed:**
  - `eval` and `new Function`.
  - Methods on instances (`socket.write` after `net.connect` is counted only at
    `connect`).
  - Worker threads.
  - Child processes that don't get the `--import` flag.
  - A process killed by a signal writes nothing.
- **Compatibility:**
  - A package's wrapped builtins are not `===` to the real ones.
  - Node 24's `require.resolve("fs")` inside a package returns a `depward-cap:` URL, and
    `require.cache` gets `depward-cap:` keys.
  - Properties that Node freezes on builtin functions (`fs.exists[util.promisify.custom]`)
    can't be wrapped, so `util.promisify(fs.exists)` calls go uncounted.

The design and the measurements are in
[ADR 0007](../../docs/adr/0007-caps-runtime-hooks.md).
