# depward

Open-source tools that protect JavaScript projects from risky dependencies, especially
when AI coding agents install packages with no human watching. depward reads registry
metadata and statically analyzes tarballs. It never runs package code.

> **Status:** pre-release. See [docs/ROADMAP.md](docs/ROADMAP.md).

| Package | Purpose |
|---|---|
| [`@depward/core`](packages/core) | Registry client, tarball reader, lockfile parsers, cache, config, reporters |
| [`@depward/analyzer`](packages/analyzer) | Static capability and risk-signal extraction from a package tarball |
| [`@depward/gate`](packages/gate) | Admission check before install: allow / ask / deny, plus agent hook adapters |
| [`@depward/diff`](packages/diff) | Behavioral diff between two versions, or across a lockfile change |
| [`@depward/mcp`](packages/mcp) | MCP server that exposes gate and diff to agents |
| [`depward`](packages/cli) | The CLI |

## Development

```bash
pnpm install --frozen-lockfile
pnpm build && pnpm lint && pnpm test && pnpm check:publish
pnpm depward -- --help
```

Security reports: see [SECURITY.md](SECURITY.md). License: [MIT](LICENSE).
