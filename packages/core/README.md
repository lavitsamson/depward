# @depward/core

Shared foundation for depward: npm registry client, in-memory tarball reader, lockfile parsers, cache, config, and reporters. It has no knowledge of policy.

> **Status:** pre-release scaffolding (Phase 0). Only `VERSION`, `DepwardError`, and the `Finding` types are exported so far; see
> the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { VERSION, compareFindings } from "@depward/core";

console.log(VERSION, [].toSorted(compareFindings));
```

Requires Node.js >= 22.15. ESM only. MIT licensed.
