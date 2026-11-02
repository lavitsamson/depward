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

## Cache

- Location: `$XDG_CACHE_HOME/depward` or the platform equivalent. Override with
  `DEPWARD_CACHE_DIR`.
- Packuments: 10 min TTL with ETag revalidation. Downloads: 24 h. Tarballs: permanent,
  keyed by integrity.
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
