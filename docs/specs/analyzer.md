# Spec: @depward/analyzer

Statically profiles one package tarball. It does not decide policy; it only describes
what the package *can* do. The gate, diff, and caps packages all consume its output.

## API

```ts
function analyzePackage(files: PackageFiles, opts?: AnalyzeOptions): PackageProfile;

interface PackageProfile {
  name: string; version: string;
  scripts: { preinstall?: string; install?: string; postinstall?: string; prepare?: string };
  capabilities: Record<Capability, CapabilityUse[]>;  // empty arrays are allowed
  signals: Signal[];                                   // suspicious patterns, with evidence
  files: FileSummary[];                                // path, size, kind, sha256, minified?
  endpoints: string[];                                 // URL/host/IP literals found
  envKeys: string[];                                   // process.env keys read (literal access)
  stats: { jsFiles: number; parsed: number; unparsed: number; bytes: number };
}

type Capability =
  | "fs" | "net" | "child_process" | "env" | "dynamic_code"
  | "native_addon" | "worker" | "dynamic_require" | "crypto" | "os_info";
```

## Parsing

- Use `acorn` with `ecmaVersion: "latest"`. Try `sourceType: "module"` first and fall
  back to `"script"`. Enable `allowHashBang` and `allowReturnOutsideFunction`.
- Files that can't be parsed are not an error. Record them in `stats.unparsed`. If they
  are `.js`, `.cjs`, or `.mjs` files, emit an `unparseable-file` signal. Skip `.ts`,
  `.jsx`, and `.tsx` with an info-level note; they are rare in published tarballs.
- Scope-aware enough to resolve these:
  - `const fs = require("fs")` and `import * as cp from "node:child_process"`;
  - destructuring such as `const { exec } = require("child_process")`;
  - aliases: `const r = require; r("net")`. This one is best-effort; flag as
    `dynamic_require` if it can't be resolved.
- Treat `node:` prefixed and bare builtin names the same. Get the list of builtins
  from `module.builtinModules`.

## Capability rules

| Capability | Detected when |
|---|---|
| `fs` | imports `fs`, `fs/promises`, `node:fs`; access to `process.binding('fs')` |
| `net` | imports `http`, `https`, `http2`, `net`, `tls`, `dgram`, `dns`; uses global `fetch`, `WebSocket`, `XMLHttpRequest`, or `EventSource` |
| `child_process` | imports `child_process`; any `process.binding('spawn_sync')` |
| `env` | any `process.env` read. Record literal keys in `envKeys` |
| `dynamic_code` | `eval`, `new Function`, `Function(...)`, the `vm` module, `setTimeout`/`setInterval` with a string argument |
| `native_addon` | `.node` files in the tarball, `bindings`/`node-gyp-build` usage, `process.dlopen` |
| `worker` | `worker_threads`, `cluster` |
| `dynamic_require` | `require(nonLiteral)`, `import(nonLiteral)`, `module.require`, `createRequire` |
| `crypto` | the `crypto` module (informational only) |
| `os_info` | the `os` module, `process.platform`, or `process.arch` used alongside `net` (informational only) |

## Risk signals (IDs are public API; add each to `docs/findings.md`)

| Signal ID | Default severity | Detection |
|---|---|---|
| `install-script` | medium | `preinstall`, `install`, or `postinstall` present (`prepare` is ignored for registry installs) |
| `install-script-network` | high | install script runs `curl`, `wget`, `node -e`, a `.js` file that uses `net`, or contains a URL |
| `env-sensitive-read` | high | reads keys matching `/TOKEN|SECRET|KEY|PASSWORD|NPM_|AWS_|GITHUB_|GH_|CI_JOB/i`, or enumerates `process.env` (`Object.keys`, spread, `JSON.stringify(process.env)`) |
| `env-exfil-pattern` | critical | the same file both does an `env-sensitive-read` and makes a `net` call |
| `fs-sensitive-path` | high | string literals referencing `.npmrc`, `.ssh`, `.aws`, `.git-credentials`, `.config/gh`, browser profile directories, or wallet keystores |
| `obfuscation` | high | string-array rotation pattern, `_0x[0-9a-f]{4,}` identifiers that make up more than 30% of identifiers, or heavy `\x`/`\u` escape density |
| `encoded-payload` | high | base64 or hex literal over 1 KB that is decoded (`Buffer.from(..., 'base64')`, `atob`) and passed to `eval`, `Function`, `vm`, or a write call |
| `high-entropy-string` | low | string literal over 200 chars with Shannon entropy above 5.2 |
| `hardcoded-endpoint` | info | URL, IP, or hostname literal. Exclude example/localhost/doc domains and the `repository`/`homepage` fields of package.json |
| `raw-ip-endpoint` | medium | an IPv4/IPv6 literal used in a network call |
| `native-binary` | medium | `.node`, ELF/Mach-O/PE executables (detected by magic bytes), or `.wasm` |
| `unparseable-file` | low | a JS file that failed to parse |
| `oversized-file` | low | a single file over 5 MB that was skipped |
| `minified-only` | info | the package ships only minified code (low average line count, high line length) |

Severity is a default; the policy layer may remap it.

## Fixtures

`packages/analyzer/fixtures/<case>/`, each containing a `package/` directory and an
`expected.json`. Tests pack the directory into a tarball in memory. For every rule,
include at least one positive fixture and one *near-miss* negative fixture. For example,
reading `process.env.NODE_ENV` must **not** trigger `env-sensitive-read`.

Synthetic attack replays (inert, using `.invalid` domains):

1. `replay-postinstall-dropper`: a postinstall script that fetches a URL and spawns `node`
   with the response.
2. `replay-token-stealer`: enumerates env vars and POSTs them.
3. `replay-obfuscated-patch`: a normal library plus one obfuscated file added.
4. `replay-worm`: reads `.npmrc` and calls a publish-like HTTP PUT to a registry URL.

## Implementation clarifications (M1.4)

These fill gaps in the tables above. They were added while implementing M1.4 and are
open for review.

- **Signal shape.** `Signal` is `{ id, severity, message, evidence[] }`, using core's
  `Evidence`. `profileFindings(profile)` turns signals into `Finding`s. A signal is
  emitted at most once per file (package-level ones once per package), with at most 10
  evidence entries plus an "and N more" entry.
- **File kinds.** `FileSummary.kind` is `js | json | source | native | wasm | other`.
  `source` means TypeScript/JSX (skipped, counted in `stats.skipped` instead of an
  "info-level note"). `.d.ts` files are `other`. Extensionless files with a `node`
  shebang are `js`. `FileSummary.bundled` marks bundler output (webpack, esbuild,
  browserify, parcel runtime markers).
- **Scope.** Bindings are tracked per file, not per lexical scope: the first binding of a
  name wins. A global (`fetch`, `eval`, `Function`, `WebSocket`, …) is only treated as the
  global when the file declares no variable, function, parameter, or import with that
  name. `require` is always `require`, because bundles pass it as a parameter.
- **`net`** also covers well-known HTTP client packages (`axios`, `node-fetch`, `got`,
  `undici`, `ws`, …). Otherwise a token stealer that uses `axios` would avoid
  `env-exfil-pattern`.
- **`native_addon`** also covers `@mapbox/node-pre-gyp`, `node-gyp-build-optional-packages`,
  and `require()` of a relative `.node` path.
- **`os_info`**: the `os` module always counts. `process.platform`/`process.arch` count
  only in a file that also has a `net` use.
- **`dynamic_code`** also covers `.constructor("…")` calls with a string argument (the
  `[].filter.constructor` trick).
- **`install-script`**: a root `binding.gyp` with no `install`/`preinstall` script
  implies `install: node-gyp rebuild`, as npm does.
- **`install-script-network`**: "a `.js` file that uses `net`" follows the file's relative
  imports transitively, up to 500 files.
- **`env-sensitive-read` key names** (changed after the Phase 1 live review, see
  `docs/benchmarks.md`): the secret words `TOKEN|SECRET|KEY|PASSWORD` match in any case;
  the vendor prefixes `NPM_|AWS_|GITHUB_|GH_|CI_JOB` match only uppercase, at the start of
  the name. npm's lowercase `npm_config_*`/`npm_package_*` variables are configuration.
- **`env-exfil-pattern`** (changed after the Phase 1 live review): instead of "same file",
  the sensitive value must flow into a network call within the file: as part of its
  arguments; through variable assignments into its arguments; or into a method call on an
  object created by a network call (`req.write(v)`, `ws.send(v)`,
  `https.request(o).end(v)`). Flow across function calls and returns is not tracked, so a
  token read in one function and sent from another is not `critical` (it is still
  `env-sensitive-read`, and Phase 3's diff flags a new env read plus new network use).
- **Flow names are scoped** (changed 2026-11-10 after next@16.4.6 was flagged `critical`
  through name collisions in its minified server runtime): every variable in a flow is
  matched by the scope that declares it, using JavaScript's rules. Scopes are the
  program, functions (parameters, `var`, hoisted functions), and blocks, `for (let …)`,
  `catch`, and `switch` for `let` / `const` / `class`. Block scopes are exact, not folded
  into the function, so a dummy `catch (t) {}` can't split a stealer's flow.
  `Object.assign(process.env, x)` (first argument) is a write, not an enumeration.
- **`endpoints`** holds normalized URLs (`scheme://host[:port]/path`, query dropped),
  hosts, or IPs. The exclusion list for `hardcoded-endpoint` (and for `endpoints`) is in
  `docs/findings.md`. `.invalid` hosts are kept, because fixtures use them.
- **`obfuscation` escape density** counts only escapes that decode to printable ASCII, so
  Unicode data tables are not flagged. Thresholds are in `docs/findings.md`.
- **Unparsed files** get no further analysis (no regex fallback).
- **Fixture `expected.json`** lists the exact set of signal IDs and non-empty
  capabilities, plus optional `envKeys`, `endpoints`, `scripts`, `files`, `stats`,
  `signalCounts`, `severityAtLeast`, and `options`.
