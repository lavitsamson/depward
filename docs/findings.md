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
- **Meaning:** code reads an environment variable whose name contains `TOKEN`, `SECRET`,
  `KEY`, or `PASSWORD` (any case) or starts with `NPM_`, `AWS_`, `GITHUB_`, `GH_`, or
  `CI_JOB` (uppercase), or enumerates the whole
  environment (`Object.keys/values/entries/assign`, `JSON.stringify`, object spread, rest
  destructuring, or `for…in` over `process.env`).
- **Fix:** check why the package needs the variable.
- **False positives:** CI detection (`GITHUB_ACTIONS`), config loaders that list the
  environment (`debug`, `dotenv`), and child-process helpers that copy it with
  `{ ...process.env }`. npm's lowercase `npm_config_*` variables do not match. Passing `process.env` whole (`{ env: process.env }`) is not flagged.

### env-exfil-pattern

- **Default severity:** critical
- **Emitted by:** `@depward/analyzer`
- **Meaning:** a value from an `env-sensitive-read` flows into a network call in the same
  file: directly in its arguments, through variables, or through a request/socket object
  (`req.write`, `ws.send`). This is the shape of a token stealer. Variables are matched
  by the scope that declares them, as JavaScript does, so a minified `e` in one function
  is not the `e` in another, while a callback still sees its outer function's `token`.
  Flow through function calls and returns is not followed. `Object.assign(process.env, x)`
  writes into the environment and is not a read.
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

## Gate: install commands (`@depward/gate`)

Emitted by `parseInstallCommand` while reading a shell command, before any registry or
tarball check. Default actions (allow / ask / deny) are applied by the policy engine.

### non-registry-source

- **Default severity:** medium (default action: ask)
- **Emitted by:** `@depward/gate` (`parseInstallCommand`)
- **Meaning:** a package spec installs from a git repository, GitHub shorthand
  (`user/repo`), a URL, a local path or tarball, or another non-npm protocol (`jsr:`,
  `patch:`), so depward's registry and tarball checks can't see what it installs.
  `package` is the alias if one was given (`foo@github:u/r`), otherwise the spec.
  `workspace:` specs are local workspace packages and don't produce this finding.
- **Fix:** install a published registry version instead, or allow the source explicitly
  once you trust it.
- **False positives:** local development (`npm i ../my-lib`) and forks you control.

### unparseable-command

- **Default severity:** medium (default action: ask)
- **Emitted by:** `@depward/gate` (`parseInstallCommand`)
- **Meaning:** the command involves a package manager, but depward can't tell what it
  installs. `package` is `(command)`; the evidence `detail` says why: a spec or program
  name computed at run time (`npm i $PKG`, `$(which npm) i x`), specs read from `xargs`,
  an invalid package spec, a shell syntax error, or nesting deeper than 8 levels.
- **Fix:** write the package names literally, then run the command again.
- **False positives:** scripts that compute versions from variables on purpose.

### global-install

- **Default severity:** info (default action: allow)
- **Emitted by:** `@depward/gate` (`parseInstallCommand`)
- **Meaning:** the package is installed globally (`-g`, `--global`,
  `--location=global`, `yarn global add`), so its binaries land on the user's `PATH`.
- **Fix:** informational. Prefer a project-local dev dependency where possible.
- **False positives:** none; it's a note.

## Gate: registry checks (`@depward/gate`)

Emitted by `checkRegistry` from registry metadata only (the packument and npm's weekly
download count). Nothing is downloaded or run. Thresholds are configurable. Default
actions are applied by the policy engine, which also escalates `low-downloads` together
with `package-too-new` to deny. When a lookup fails (network, timeout), the check returns
the error instead of a finding, and the policy engine applies `onError` (default: ask).

### package-not-found

- **Default severity:** high (default action: deny)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the registry has no package with this name. AI agents often invent
  plausible names, and attackers register such names once they spread ("slopsquatting").
  The message suggests the closest popular package when one is near.
- **Fix:** check the name. Use the suggested package if it is what you meant.
- **False positives:** a private package queried against the wrong registry. Check the
  scope's registry in `.npmrc`.

### known-hallucinated-name

- **Default severity:** critical (default action: deny)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the name is in `data/hallucinated-names.json`: AI models are publicly
  documented to invent it. It is flagged even if someone has since registered the
  name, because that someone is often an attacker (or a placeholder). The evidence
  links the public source; the message names the real package.
- **Fix:** install the suggested package.
- **False positives:** you really want the package that now holds the name. Allow it
  by `name@version` in the config.

### version-not-found

- **Default severity:** high (default action: deny)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** no published version matches the requested range, version, or
  dist-tag. The evidence lists the package's dist-tags.
- **Fix:** pick an existing version, for example `latest`.
- **False positives:** a version published seconds ago that the registry cache hasn't
  served yet.

### version-too-new

- **Default severity:** medium (default action: ask)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the resolved version was published less than `minVersionAgeDays` (7)
  ago. Most malicious releases are found and removed within days, so waiting a week
  avoids most of them. The message suggests the newest version that is old enough,
  within the requested range if possible.
- **Fix:** install the suggested older version, or wait.
- **False positives:** urgent security fixes. Allow that exact `name@version`.

### package-too-new

- **Default severity:** medium (default action: ask; deny together with `low-downloads`)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the package was first published less than `minPackageAgeDays` (30) ago.
- **Fix:** prefer an established package, or review this one before allowing it.
- **False positives:** new packages from people you trust.

### low-downloads

- **Default severity:** medium (default action: ask; deny together with `package-too-new`)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the package had fewer than `minWeeklyDownloads` (500) downloads last
  week. Not checked on non-public registries, which have no download counts.
- **Fix:** prefer a widely used alternative, or review the package before allowing it.
- **False positives:** niche but legitimate packages.

### typosquat-suspect

- **Default severity:** high (default action: ask)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the name is close to a package in `data/popular-packages.json` and that
  package has at least 100× more weekly downloads. Close means an edit distance of at
  most 2 (at most 1 when the popular name has 5 characters or fewer), where swapping two
  adjacent letters counts as one edit (`axois` vs `axios`), or the same
  name after removing `-`, `_`, `.`, and the scope (`types-node` vs `@types/node`).
  Packages on the popular list are never flagged, and names in the same scope are
  never compared: only the scope's owner can publish there. Unknown download counts
  count as 0. Evidence lists up to 3 similar popular packages.
- **Fix:** install the popular package if that is what you meant.
- **False positives:** small legitimate packages with names near popular ones
  (`preact`-style forks, plugins). Allow them by name.

### publisher-changed

- **Default severity:** medium (default action: ask)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the resolved version's `_npmUser` (the account that published it) did
  not publish any of the previous 5 versions (by publish time) and is not an established
  maintainer. Established means listed in the `maintainers` of the version just before
  and of the newest version published at least 30 days earlier, so an account that was
  added recently never counts. Account takeovers usually look like this. The evidence
  lists the earlier publishers.
- **Fix:** check the project's changelog or repository for the new maintainer.
- **False positives:** new team members' first releases, and switching to trusted
  publishing (the publisher becomes the CI identity), unless that account was already
  a listed maintainer.

### maintainer-added-recently

- **Default severity:** low (default action: allow)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** a version published in the last 30 days lists a maintainer that the
  newest version older than 30 days doesn't. This is about the package, not the
  resolved version, so it has no `version`. It isn't checked for packages with no
  version older than 30 days (see `package-too-new`).
- **Fix:** informational. Combined with other findings, it suggests a takeover.
- **False positives:** normal team growth.

### provenance-dropped

- **Default severity:** high (default action: ask)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the resolved version has no provenance attestation, but at least one of
  the previous 5 versions (by publish time) had one. A stable version is compared only
  with earlier stable versions, because projects often build prereleases on a different
  pipeline (rxjs's 8.0 alphas had provenance; its 7.x line never did). A prerelease is
  compared with every earlier version. A release from a stolen token is usually
  published from a laptop, not the project's CI. Attestations are detected by
  presence only; they are not cryptographically verified yet.
- **Fix:** use the last version with provenance until the maintainers explain the change.
- **False positives:** a maintainer publishing manually once (for example a hotfix).

### deprecated

- **Default severity:** low (default action: allow)
- **Emitted by:** `@depward/gate` (`checkRegistry`)
- **Meaning:** the resolved version is deprecated. The evidence holds the deprecation
  message, escaped and truncated to 200 characters. When a range allows other versions,
  the resolver already prefers non-deprecated ones, as npm does.
- **Fix:** follow the deprecation message, usually by upgrading.
- **False positives:** none; it's a note.

## Gate: tarball checks (`@depward/gate`)

Emitted by `checkTarball` (and `checkPackage`), which downloads the resolved version's
tarball, verifies it against the registry's integrity hash, reads it in memory, and runs
the analyzer. Every analyzer signal above becomes a finding with the same ID and
severity, reported under the requested package name and version (never the archive's
own `package.json`). Escalations (`install-script` together with `package-too-new` or
`low-downloads` → deny, and any `critical` → deny) are applied by the policy engine.
Network failures and timeouts are returned as errors, and the policy engine applies
`onError`. Problems with the archive itself are findings, so a crafted archive can't
downgrade its own result to `onError`.

### tarball-integrity-mismatch

- **Default severity:** critical (default action: deny)
- **Emitted by:** `@depward/gate` (`checkTarball`)
- **Meaning:** the downloaded tarball doesn't match the `dist.integrity` (or
  `dist.shasum`) the registry published for the version, or the version has no usable
  hash. The bytes may have been tampered with between the registry and you: a proxy,
  a mirror, or a poisoned cache. Nothing in the archive was analyzed.
- **Fix:** don't install it. Retry from the public registry, and check proxies,
  mirrors, and the depward cache directory.
- **False positives:** a misbehaving registry mirror that rewrites tarballs.

### tarball-unsafe

- **Default severity:** high (default action: deny)
- **Emitted by:** `@depward/gate` (`checkTarball`)
- **Meaning:** the archive can't be analyzed safely, so nothing in it was checked. It
  contains entries with absolute paths, `..`, or links pointing outside the package;
  it is corrupt or has no readable `package.json` object; or it exceeds a limit
  (50 MB compressed, 200 MB unpacked, 20,000 entries). The evidence `detail` says which.
- **Fix:** don't install it. If it's a large package you trust, raise the limit in the
  config or allow that exact `name@version`.
- **False positives:** very large legitimate packages (some platform binaries) over
  the size limits.
