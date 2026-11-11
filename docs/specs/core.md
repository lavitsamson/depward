# Spec: @depward/core

The shared foundation for every other package. It must have no knowledge of policy.

## Public API (initial)

```ts
interface RegistryClient {
  packument(name: string): Promise<Packument | null>;        // null means a 404
  versionMeta(name: string, version: string): Promise<VersionMeta | null>;
  weeklyDownloads(name: string): Promise<number | null>;
  attestations(name: string, version: string): Promise<Attestations | null>;
  tarball(meta: VersionMeta): Promise<Uint8Array>;           // integrity-verified
}

function createRegistryClient(opts?: {
  registry?: string;          // default: from the user's .npmrc, else https://registry.npmjs.org
  token?: string;             // default: from the user's .npmrc; never logged
  cache?: Cache;              // default: disk cache in the XDG cache dir
  timeoutMs?: number;         // default: 8000 per request
  fetch?: typeof fetch;       // injectable for tests
}): RegistryClient;

function readTarball(bytes: Uint8Array, limits?: TarLimits): PackageFiles; // in memory
function parseLockfile(path: string, contents: string): Lockfile;
function diffLockfiles(base: Lockfile, head: Lockfile): LockfileDiff;
function readFileAtRef(ref: string, path: string, cwd: string): Promise<string | null>;
function loadConfig(cwd: string): Promise<DepwardConfig>;

type Severity = "info" | "low" | "medium" | "high" | "critical";
interface Finding {
  id: string; severity: Severity; package: string; version?: string;
  message: string; evidence: Evidence[]; docsUrl: string;
}
interface Evidence { file?: string; line?: number; snippet?: string; detail?: string }
```

## Registry endpoints (verify against current npm docs before implementing)

- Packument: `GET {registry}/{name}`. Scoped names are URL-encoded as `@scope%2fname`.
  Use the full document, not the abbreviated `application/vnd.npm.install-v1+json` one,
  because `time`, `maintainers`, and per-version `_npmUser` are needed.
- Downloads: `GET https://api.npmjs.org/downloads/point/last-week/{name}`. This only
  exists for the public registry; return `null` for others.
- Attestations: `dist.attestations` in version metadata. The attestations endpoint is
  linked from there. In v0.x, only record whether attestations are *present*;
  cryptographic verification comes later and needs its own ADR.

## Tarball reader

- Verify the SRI `sha512` from `dist.integrity` before decompressing. A mismatch is an
  error with the `INTEGRITY_MISMATCH` code.
- Support ustar, GNU long names, and pax extended headers. Normalize the `package/`
  prefix away.
- Limits: compressed size 50 MB, uncompressed 200 MB, 20,000 entries. Exceeding any
  limit produces a typed error. The gate converts this into a finding, not a crash.
- Reject path entries containing `..` or absolute paths. Record symlinks and hardlinks as
  metadata but never follow them.

## Lockfiles

| Format | Detection | Notes |
|---|---|---|
| npm v2/v3 | `package-lock.json`, `lockfileVersion >= 2` | Use the `packages` map. Keys are `node_modules/...` paths |
| pnpm | `pnpm-lock.yaml`, `lockfileVersion` 6.x / 9.x | v9 separates `packages` from `snapshots` |
| yarn v1 | `yarn.lock` with a `# yarn lockfile v1` header | A custom parser is needed (not YAML) |
| yarn berry | `yarn.lock` containing `__metadata` | Parse as YAML |
| bun | `bun.lock` (JSONC text) | Ignore the binary `bun.lockb`; emit an `unsupported-lockfile` info finding |

Entries from non-registry sources (git, tarball URL, `file:`, `link:`, `workspace:`) are
kept and tagged with `source`, so that the gate and diff can treat them specially.

Normalized entry (implemented in M1.3):

```ts
interface LockfileEntry {
  name: string; version: string;             // key is `${name}@${version}`
  source: "registry" | "git" | "tarball" | "file" | "link" | "workspace"
        | "bundled"                           // npm `inBundle`: shipped inside the parent tarball
        | "other";                            // yarn `patch:` / `exec:`
  integrity: string | null;                   // SRI; null for yarn berry (its checksum is not SRI)
  resolved: string | null;
  dev: boolean | null;                        // null when the format doesn't record it
  optional: boolean | null;                   // (yarn v1, yarn berry, bun)
}
```

- A package installed at several paths is dev/optional only if every copy is.
- pnpm v9 has no dev flag. Dev-ness comes from walking `snapshots` from the importers.
  pnpm 11+ files can hold two YAML documents (an env document with pnpm itself and
  config dependencies, then the project). Every document is read, and env roots count
  as prod.
- `diffLockfiles` keys on `name@version`. A version bump is one `removed` plus one
  `added`, and Phase 3 pairs them by name. `changed` means the same key with a
  different `source`, `integrity`, `dev`, or `optional`, or a different `resolved` when
  neither side has integrity (for example a new git commit). A field one side records as
  `null` is not compared.

## Cache

- Location: `$XDG_CACHE_HOME/depward` or the platform equivalent. Override with
  `DEPWARD_CACHE_DIR`.
- Packuments: 10 min TTL with ETag revalidation. Downloads: 24 h. Tarballs: permanent,
  keyed by integrity. Analysis results (written by the gate, ADR 0005): permanent, keyed
  by integrity, analyzer version and revision, and limits.
- Atomic writes (temp file + rename). Safe when several processes run at once.

## Config (`depward.config.json` or the `"depward"` key in package.json)

JSON only, to avoid a dependency. Shape:

```json
{
  "policy": { "<finding-id>": "allow" | "ask" | "deny" },
  "thresholds": { "minVersionAgeDays": 7, "minPackageAgeDays": 30, "minWeeklyDownloads": 500 },
  "allow": ["@myorg/*"],
  "deny": ["event-stream@3.3.6"],
  "onError": "ask",
  "registry": "https://registry.npmjs.org"
}
```

`loadConfig(cwd, { path? })` reads `cwd/depward.config.json`, else the `"depward"` key of
`cwd/package.json`, else the defaults. Parent directories are not searched. `path`
(`--config`) reads that file instead, and it must exist (`NOT_FOUND`). `parseConfig`
validates strictly: unknown keys, unknown thresholds, actions other than
`allow`/`ask`/`deny`, negative or non-numeric thresholds, non-http(s) registries, and
files over 1 MB are all `INVALID_CONFIG`. A typo such as `"denny"` must not silently
drop a deny list. `$schema` is allowed. Core checks the shape only. What the actions
mean is the gate's policy engine.

Offline mode: `createRegistryClient({ offline })`, default `DEPWARD_OFFLINE=1` in
`env`, serves cached packuments, downloads, and tarballs at any age, and never touches
the network. Anything uncached fails with `OFFLINE`.

## Reporters (M1.5)

Pure functions from `Finding[]` to a string that ends with a newline. Each one sorts its
input (`sortFindings`: severity, package, id, then version, message, and first evidence
location), so output never depends on input order. `renderReport(format, findings, opts)`
dispatches on `terminal | json | markdown | sarif`.

- **Terminal** (`renderTerminal`): a summary line, then one block per finding (severity,
  id, `name@version`, message, evidence, docs URL). Color is opt-in through
  `colorEnabled(env, isTTY)`: `NO_COLOR` (non-empty) turns it off, `FORCE_COLOR` turns it
  on (`0`/`false` turn it off), `TERM=dumb` turns it off; otherwise color only on a TTY.
- **JSON** (`renderJson`): `{ reportVersion: 1, tool, summary: { total, critical, high,
  medium, low, info }, findings }` with keys in a fixed order. No escaping beyond JSON's.
- **Markdown** (`renderMarkdown`): the table and `<details>` shape from `diff.md`, one
  section per package, expanded when its worst finding is `high` or above.
- **SARIF 2.1.0** (`renderSarif`): one run. Rules are the distinct finding IDs, tagged
  `security`, with `security-severity` critical 9.5, high 8.0, medium 5.5, low 3.0, and
  none for info. Levels: critical/high → `error`, medium → `warning`, low/info → `note`.
  Every result has one location from `opts.locate(finding)` (default `package.json`,
  line 1; lockfile mode should point at the lockfile) and a
  `partialFingerprints.primaryLocationLineHash` derived from (id, package, version).
  Validated against the official OASIS schema (`fixtures/schemas/`) in tests.

**Untrusted text.** Terminal, Markdown, and SARIF output pass every package-controlled
string through `escapeUnsafe`, which turns C0/C1 controls (so ANSI escapes), zero-width
and bidi characters, and line separators into visible escapes (`\x1b`, `‮`), and caps
snippets at 200 characters. Markdown additionally entity-encodes `& < > " '`,
backslash-escapes `` \ ` * _ [ ] # | ~ : ``, puts names and snippets in `<code>`, adds a
zero-width space after `@` (no mentions), and only links docs URLs that are `https:`.
