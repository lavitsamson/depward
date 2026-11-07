# @depward/core

Shared foundation for depward: npm registry client, in-memory tarball reader, lockfile parsers, cache, config, and reporters. It has no knowledge of policy.

> **Status:** pre-release (Phase 1). The registry client, caches, integrity
> verification, tar reader, and lockfile parsers are implemented; config and reporters
> are next. See the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { createRegistryClient, readTarball } from "@depward/core";

const registry = createRegistryClient(); // reads ~/.npmrc and ./.npmrc; disk cache in the XDG cache dir

const meta = await registry.versionMeta("semver", "latest");
console.log(meta?.version, await registry.weeklyDownloads("semver"));
console.log("provenance:", (await registry.attestations("semver", "latest")) !== null);

const tgz = await registry.tarball(meta); // verified against dist.integrity before it is returned
const { files } = readTarball(tgz); // in memory; rejects traversal and escaping links
console.log(files.map((f) => f.path));
```

## Registry client

- Full packuments (needed for `time`, `maintainers`, and `_npmUser`). Version metadata
  and attestation presence come from the same cached document.
- Cache: packuments 10 min with `ETag` revalidation, downloads 24 h, tarballs permanent
  and keyed by integrity. Override the location with `DEPWARD_CACHE_DIR`.
- `.npmrc`: `registry`, `@scope:registry`, and `//host/path/:_authToken` / `:_auth`.
  Credentials are only sent to URLs under their `//host/path/` prefix, are dropped on
  redirects to other hosts, and print as `[redacted]`.
- Every request has a timeout (default 8 s) and a body-size cap.

## Tarball reader

`readTarball(bytes, limits?)` reads gzip'd ustar, pax, and GNU long-name archives in
memory and strips the leading `package/` segment. It never writes to disk or follows
links. Limits: 50 MB compressed, 200 MB uncompressed (enforced while inflating), 20,000
entries. Absolute paths, `..`, and links that leave the package throw `UNSAFE_PATH`.

## Lockfiles

```js
import { diffLockfiles, parseLockfile, readFileAtRef } from "@depward/core";
import { readFile } from "node:fs/promises";

const head = parseLockfile("pnpm-lock.yaml", await readFile("pnpm-lock.yaml", "utf8"));
const baseText = await readFileAtRef("origin/main", "pnpm-lock.yaml", process.cwd()); // git, no shell
const base = baseText === null ? null : parseLockfile("pnpm-lock.yaml", baseText);
if (base) console.log(diffLockfiles(base, head).added.map((e) => `${e.name}@${e.version} (${e.source})`));
```

Supported: `package-lock.json` / `npm-shrinkwrap.json` (v2, v3), `pnpm-lock.yaml` (6.x, 9.x,
including pnpm 11's two-document files), `yarn.lock` (v1 and berry), and `bun.lock`.
Older formats and `bun.lockb` give an `unsupported-lockfile` finding. Each entry is tagged
with its `source` (`registry`, `git`, `tarball`, `file`, `link`, `workspace`, `bundled`,
`other`). `dev` and `optional` are `null` when the format doesn't record them.

## Testing

`@depward/core/testing` exports `createFixtureRegistryClient(dir)`, an offline client
that serves recorded responses. `packTarball(entries)` builds an npm-style tarball in
memory, for tests that need one. See [`fixtures/registry/`](../../fixtures/registry/README.md).

Requires Node.js >= 22.15. ESM only. MIT licensed.
