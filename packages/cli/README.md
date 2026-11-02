# depward

Protects JavaScript projects, and the AI coding agents working in them, from risky npm dependencies. Reads registry metadata and statically analyzes tarballs; never runs package code.

> **Status:** pre-release scaffolding (Phase 0). Only `VERSION` is exported so far; see
> the [roadmap](../../docs/ROADMAP.md).

## Example

```sh
npm install --global depward@0.0.0   # pin an exact version
depward --version
```

Requires Node.js >= 22.15. ESM only. MIT licensed.
