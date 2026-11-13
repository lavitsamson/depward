# M4.0 spike: per-package builtins with `module.registerHooks`

Throwaway prototype for roadmap milestone M4.0. Results and decision:
[`docs/adr/0007-caps-runtime-hooks.md`](../../docs/adr/0007-caps-runtime-hooks.md).
Nothing here is published or imported by the packages; `@depward/caps` (M4.1+) is
written from scratch using the ADR.

| Path | What it is |
|---|---|
| `register.mjs` | Hooks + runtime: redirects capability builtins imported from `node_modules` to `depward-cap:<module>?pkg=<name>`, serves a per-package Proxy, wraps `fetch`, `process.getBuiltinModule`, `process.env` with stack attribution |
| `app/node_modules/*` | Synthetic, inert fixture packages (Express-like, Prisma-like, ESM, bundled, nested, scoped, bypass probes) |
| `app/checks.mjs`, `app/enforce.mjs`, `app/cjs-entry.cjs` | Behavior probes for spec questions 1–4 |
| `run-checks.mjs` | Reruns every probe and compares with the answers recorded in the ADR |
| `bench/run.mjs` | Startup, per-call and request benchmarks (question 5) |

```bash
node spikes/m4.0-caps/run-checks.mjs      # exits 1 if an answer changed
node spikes/m4.0-caps/bench/run.mjs 5     # medians over 5 alternating rounds
```

The fixture packages never touch the network: `fetch` uses `data:` URLs and the server
listens on 127.0.0.1.
