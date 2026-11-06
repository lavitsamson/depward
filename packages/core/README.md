# @depward/core

Shared foundation for depward: npm registry client, in-memory tarball reader, lockfile parsers, cache, config, and reporters. It has no knowledge of policy.

> **Status:** pre-release (Phase 1). The registry client, caches, and integrity
> verification are implemented; the tar reader, lockfile parsers, config, and reporters
> are next. See the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { createRegistryClient } from "@depward/core";

const registry = createRegistryClient(); // reads ~/.npmrc and ./.npmrc; disk cache in the XDG cache dir

const meta = await registry.versionMeta("semver", "latest");
console.log(meta?.version, await registry.weeklyDownloads("semver"));
console.log("provenance:", (await registry.attestations("semver", "latest")) !== null);

const tgz = await registry.tarball(meta); // verified against dist.integrity before it is returned
console.log(tgz.byteLength, "bytes");
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

## Testing

`@depward/core/testing` exports `createFixtureRegistryClient(dir)`, an offline client
that serves recorded responses. See [`fixtures/registry/`](../../fixtures/registry/README.md).

Requires Node.js >= 22.15. ESM only. MIT licensed.
