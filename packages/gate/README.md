# @depward/gate

Answers one question before anything is installed: should this package or install command be allowed? The result is `allow`, `ask`, or `deny`, with reasons.

> **Status:** pre-release scaffolding (Phase 0). Only `VERSION` is exported so far; see
> the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { VERSION } from "@depward/gate";

console.log(VERSION);
```

Requires Node.js >= 22.15. ESM only. MIT licensed.
