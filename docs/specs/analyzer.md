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
