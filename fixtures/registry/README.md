# Registry fixtures

Offline registry responses served by `createFixtureFetch` / `createFixtureRegistryClient`
from `@depward/core/testing`. The default test run never touches the network.

| Path | Served for |
|---|---|
| `packuments/<name>.json` | `GET {registry}/{name}` (full packument) |
| `downloads/<name>.json` | `GET https://api.npmjs.org/downloads/point/last-week/{name}` |
| `tarballs/<file>.tgz` | any URL whose path ends in `/-/<file>.tgz` |

Scoped names use `+` in place of `/`: `@scope/name` → `@scope+name.json`.

All packages named `depward-fixture-*` / `@depward-fixture/*` are **synthetic and inert**.
They only use `example.invalid` addresses. Never add real malware here (see CLAUDE.md).

`scripts/record-registry-fixture.ts <name>` records a real public packument, trimmed to
its newest versions, for tests that need realistic data.

## Rebuilding `depward-fixture-stable-2.0.0.tgz`

It is a two-file ustar archive (`package/package.json`, `package/index.js`) made with
`tar --format=ustar --owner=0 --group=0 --mtime=2020-01-01` and `gzip -n -9`. If you
rebuild it, update `dist.integrity` and `dist.shasum` for 2.0.0 in
`packuments/depward-fixture-stable.json`.
