# Finding ID catalog

Finding IDs are stable public API. Every ID emitted anywhere must have an entry here.
Format: `### <id>`, then default severity, which package emits it, what it means, how to
fix or suppress it, and false-positive notes.

<!-- Claude Code: add entries as you implement rules. See specs/analyzer.md, gate.md, diff.md. -->

### unsupported-lockfile

- **Default severity:** info
- **Emitted by:** `@depward/core` (`parseLockfile`)
- **Meaning:** the lockfile was recognized but its format can't be read, so none of its
  dependencies were checked. Formats: npm `lockfileVersion` 1, pnpm lockfiles older
  than 6.0 (or newer than 9.x), and the binary `bun.lockb`. `package` is the lockfile path.
- **Fix:** upgrade the lockfile. Run npm 7 or newer, pnpm 8 or newer, or
  `bun install --save-text-lockfile`.
- **False positives:** none. It is informational, and it means depward saw nothing.

## Analyzer signals (`@depward/analyzer`)

Each signal is emitted at most once per file (or once per package for package-level
signals), with up to 10 evidence entries. Evidence comes from package content and is
stripped of control characters and truncated. Severities are defaults; policy may remap.

### install-script

- **Default severity:** medium
- **Emitted by:** `@depward/analyzer`
- **Meaning:** the package has a `preinstall`, `install`, or `postinstall` script, so it
  runs code when installed. Like npm, a root `binding.gyp` with neither `install` nor
  `preinstall` counts as `install: node-gyp rebuild`. `prepare` is ignored because npm
  does not run it for registry installs.
- **Fix:** install with scripts disabled (`ignore-scripts=true`), or allow this package
  explicitly once you have reviewed the script.
- **False positives:** common for native addons (`node-gyp rebuild`, `prebuild-install`).

### install-script-network

- **Default severity:** high
- **Emitted by:** `@depward/analyzer`
- **Meaning:** an install script can reach the network: it runs `curl`/`wget`, a Windows
  download tool, or `node -e`; contains a URL; or runs a package JS file that (directly
  or through its relative imports) uses a `net` capability.
- **Fix:** review the script and what it downloads. Prefer packages that ship prebuilt
  binaries inside the tarball.
- **False positives:** binary downloaders (`esbuild`-style or `prebuild-install`
  fallbacks) do this legitimately.

### env-sensitive-read

- **Default severity:** high
- **Emitted by:** `@depward/analyzer`
- **Meaning:** code reads an environment variable whose name matches
  `/TOKEN|SECRET|KEY|PASSWORD|NPM_|AWS_|GITHUB_|GH_|CI_JOB/i`, or enumerates the whole
  environment (`Object.keys/values/entries/assign`, `JSON.stringify`, object spread, rest
  destructuring, or `for…in` over `process.env`).
- **Fix:** check why the package needs the variable.
- **False positives:** CI detection (`GITHUB_ACTIONS`), npm config reads
  (`npm_config_*`), and child-process helpers that copy the environment with
  `{ ...process.env }`. Passing `process.env` whole (`{ env: process.env }`) is not flagged.

### env-exfil-pattern

- **Default severity:** critical
- **Emitted by:** `@depward/analyzer`
- **Meaning:** one file both triggers `env-sensitive-read` and has a `net` capability:
  the shape of a token stealer.
- **Fix:** treat as malicious until reviewed. Do not install.
- **False positives:** SDKs that read their own API key from the environment and call
  their own API. Review the endpoint in the evidence.

### fs-sensitive-path

- **Default severity:** high
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a string literal names a credential location as path segments: `.npmrc`,
  `.ssh` (or `id_rsa`/`id_ed25519`), `.aws`, `.git-credentials`, `.config/gh`, a
  browser profile (`Chrome/User Data`, `.mozilla/firefox`, `Login Data`, …), or a wallet
  keystore (`.ethereum/keystore`, `wallet.dat`, `.electrum`, `.solana/id.json`, Exodus,
  the MetaMask extension ID).
- **Fix:** review what the code does with the path.
- **False positives:** npm tooling that legitimately reads `.npmrc`; SSH clients.

### obfuscation

- **Default severity:** high
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a file shows obfuscator output: a string-array rotation loop
  (`a.push(a.shift())` in a loop, in a function that calls `parseInt`), more than 30% of
  identifiers shaped like `_0x1a2b`, or at least 32 `\x`/`\u` escapes of *printable ASCII*
  making up 30% or more of all string-literal characters.
- **Fix:** treat as suspicious; legitimate packages rarely ship obfuscated code.
- **False positives:** commercial packages that obfuscate on purpose. Escapes of non-ASCII
  data tables (Unicode ranges, entity maps) do not count.

### encoded-payload

- **Default severity:** high
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a base64/base64url/hex literal over 1 KB is decoded (`Buffer.from(x,
  "base64"|"hex")`, `atob`) and the result reaches `eval`, `Function`, `vm`, `_compile`,
  or a write call (`writeFile*`, `appendFile*`, `write*`), directly or through variables
  in the same file.
- **Fix:** treat as malicious until reviewed.
- **False positives:** embedded WASM or fonts written to a cache directory.

### high-entropy-string

- **Default severity:** low
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a string literal longer than 200 characters has Shannon entropy above 5.2
  bits per character (random-looking data such as keys or encrypted blobs).
- **Fix:** usually informational.
- **False positives:** embedded base64 assets, hash tables, test vectors.

### hardcoded-endpoint

- **Default severity:** info
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a URL, IP, or hostname literal in JS, or a URL in `package.json` outside
  the documentation fields (`repository`, `homepage`, `bugs`, `author`, `contributors`,
  `maintainers`, `funding`, `license`). Bare hostnames count when they end in a common TLD
  or are a `host`/`hostname` value. Loopback, `localhost`, RFC 2606/6761 reserved names
  (`example.com`, `*.example`, `*.test`, `*.localhost`, `*.local`), and common
  documentation or XML-namespace hosts (`www.w3.org`, `github.com`, `nodejs.org`, …) are
  dropped.
- **Fix:** informational; used by diff to spot new endpoints.
- **False positives:** expected for any network client.

### raw-ip-endpoint

- **Default severity:** medium
- **Emitted by:** `@depward/analyzer`
- **Meaning:** an IPv4/IPv6 literal (in a URL, as a whole literal, as a `host` value, or
  in a string constant) is passed to a network call (`fetch`, `http(s)`, `net`, `tls`,
  `dgram`, a known HTTP client, `WebSocket`). Loopback and `0.0.0.0` are ignored.
- **Fix:** check what the address is. Cloud metadata (`169.254.169.254`) is a red flag.
- **False positives:** LAN device SDKs, DNS clients with default resolvers.

### native-binary

- **Default severity:** medium
- **Emitted by:** `@depward/analyzer`
- **Meaning:** the tarball contains a `.node` addon, an ELF, Mach-O, or PE executable
  (by magic bytes), or a WebAssembly module. Native code cannot be analyzed statically.
- **Fix:** prefer packages that build from source, or verify provenance.
- **False positives:** expected for prebuilt native addons (`esbuild`, `sharp`, …).

### unparseable-file

- **Default severity:** low
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a `.js`/`.cjs`/`.mjs` file (or an extensionless `node` shebang script)
  failed to parse as both an ES module and a script, or is too deeply nested to walk, so
  it was not analyzed. TypeScript
  and JSX sources are skipped silently (counted in `stats.skipped`).
- **Fix:** review the file manually.
- **False positives:** syntax newer than the bundled acorn supports.

### oversized-file

- **Default severity:** low
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a JS file is larger than the per-file limit (default 5 MB) and was skipped.
- **Fix:** review manually, or raise `maxFileBytes`.
- **False positives:** large bundles and generated data files.

### minified-only

- **Default severity:** info
- **Emitted by:** `@depward/analyzer`
- **Meaning:** every JS file of 512 bytes or more looks minified (a `.min.js` name, an
  average line length over 250 characters, or at most 3 lines and over 2,000 characters),
  so findings carry less context.
- **Fix:** informational.
- **False positives:** common for browser-oriented packages.
