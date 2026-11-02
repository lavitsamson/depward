# @depward/diff

Behavioral diff between two versions of an npm package, or across a lockfile change. Catches malicious updates to packages you already trust.

> **Status:** pre-release scaffolding (Phase 0). Only `VERSION` is exported so far; see
> the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { VERSION } from "@depward/diff";

console.log(VERSION);
```

Requires Node.js >= 22.15. ESM only. MIT licensed.
