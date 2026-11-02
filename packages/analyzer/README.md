# @depward/analyzer

Statically profiles an npm package tarball: what it *can* do (filesystem, network, child processes, env access, dynamic code) and which risk signals it shows. It never executes package code.

> **Status:** pre-release scaffolding (Phase 0). Only `VERSION` is exported so far; see
> the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { VERSION } from "@depward/analyzer";

console.log(VERSION);
```

Requires Node.js >= 22.15. ESM only. MIT licensed.
