# @depward/caps

Per-package least privilege for npm dependencies. It writes a capability lockfile,
`capabilities.lock.json`, that records what each locked package can do according to
static analysis (`fs`, `net`, `child_process`, `env`, ...). Package code is never run:
tarballs are fetched, checked against their integrity hash, and analyzed in memory.

> **Status:** Phase 4 in progress. M4.1 (`scanCapabilities`, `depward caps scan`) is
> done. `caps check` / `caps approve` (M4.2) and the runtime layer
> (`@depward/caps/register`, M4.3–M4.4) are next. See the
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
Only registry packages are listed. Workspace, link, file, bundled, git and tarball-URL
entries are reported as skipped.
