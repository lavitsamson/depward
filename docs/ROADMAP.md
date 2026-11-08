# depward roadmap

Build order: **0 → 1 → 2 → 3 → 4**. Phases 2 and 3 (gate and diff) are the first
public release. Both depend on the shared foundation built in Phase 1. (The former
Phase 5, HTML to PDF, moved to its own repository: ADR 0002.)

```
                 ┌──────────────┐
                 │ @depward/core│  registry · tarball · lockfiles · cache · config · reporters
                 └──────┬───────┘
                 ┌──────┴───────────┐
                 │ @depward/analyzer│  static capabilities + risk signals
                 └──┬────────┬──────┘
          ┌─────────┘        └─────────┐
   ┌──────┴──────┐            ┌────────┴────┐        ┌──────────────┐
   │@depward/gate│            │@depward/diff│        │@depward/caps │ (Phase 4)
   └──┬──────┬───┘            └──┬──────┬───┘        └──────────────┘
      │      └──────┬────────────┘      │
   CLI/hooks   @depward/mcp      GitHub Action
```

---

## Phase 0 — Scaffolding and our own supply-chain hygiene

- [x] pnpm workspace, `tsconfig.base.json`, tsdown, vitest, and oxlint configured
- [x] `.npmrc` with `ignore-scripts=true`. `pnpm-workspace.yaml` with
      `minimumReleaseAge` and an empty `onlyBuiltDependencies` (pnpm 11+ replaced it
      with `allowBuilds: {}` plus `strictDepBuilds: true`; see ADR 0001)
- [x] CI with three jobs: lint, test, check:publish. Matrix: Node 22 and 24, on Linux,
      macOS, and Windows. Actions pinned by SHA
- [ ] changesets configured. Release workflow uses npm trusted publishing (OIDC) with
      provenance (written; needs `repository.url` and npm trusted-publisher setup)
- [x] `docs/findings.md` (empty catalog), `docs/adr/0001-esm-only-node22.md`,
      `SECURITY.md`, MIT `LICENSE`
- [x] Empty package skeletons that build and export a version constant: `core`,
      `analyzer`, `gate`, `diff`, `mcp`, and `cli` (published as `depward`). `caps` is
      scaffolded in Phase 4

**Definition of done:** `pnpm build && pnpm lint && pnpm test && pnpm check:publish`
passes in CI on all three operating systems.

---

## Phase 1 — Foundation: core and analyzer

### M1.1 Registry client (`@depward/core`)
- [x] Fetch the packument (full document, which is needed for `time`, `_npmUser`, and
      `maintainers`), plus version metadata, download counts, and attestations
- [x] ETag-aware disk cache (XDG cache dir), with TTLs configurable per data type
- [x] Custom registry URL and auth token read from the user's `.npmrc`. Tokens are never
      logged
- [x] Recorded-fixture `RegistryClient` for tests

### M1.2 Tarball reader
- [x] Fetch the tarball and verify `dist.integrity` (SRI sha512) **before** reading it
- [x] In-memory gunzip plus a ustar/pax reader. Reject path traversal, absolute paths,
      and escaping symlinks. Enforce size limits
- [x] Content-addressed cache keyed by integrity

### M1.3 Lockfile parsers
- [x] package-lock v2/v3, pnpm-lock (v6 and v9 formats), yarn v1, yarn berry, and
      `bun.lock` (text format)
- [x] Normalized output: `Map<"name@version", {integrity, resolved, dev, optional}>`
- [x] `diffLockfiles(a, b)` returns added, removed, and changed entries
- [x] Read a lockfile at a git ref via `git show <ref>:<path>`, using `execFile` with no
      shell

### M1.4 Analyzer (`@depward/analyzer`)
- [x] File classification: JS, JSON, native binaries, minified or bundled code, other
- [x] Every rule in `docs/specs/analyzer.md`, each with positive and negative fixtures
- [x] `analyzePackage(tarball) → PackageProfile`. Target: under 300 ms for a typical
      package (under 1 MB unpacked)

### M1.5 Reporters
- [x] Terminal (with color and a `NO_COLOR` fallback), JSON, Markdown, SARIF 2.1.0

**Definition of done:** `analyzePackage` produces a correct profile for 30 synthetic
fixtures and for 20 real popular packages (in a live test). No popular package
gets a `critical` finding unless that is clearly correct, and each one is reviewed.

**Status:** met on 2026-11-07. 53 synthetic fixtures; 20 popular packages with no criticals.
Review: `docs/benchmarks.md` § Phase 1. Live test: `test/live/popular-packages.test.ts`.

---

## Phase 2 — `@depward/gate`: admission control for agents (idea #2) → release 0.1

Work order: M2.1, **M2.9**, M2.2, M2.3, … (the typosquat check in M2.2 needs the data
files from M2.9).

- [x] M2.1 Install-command tokenizer (npm, pnpm, yarn, bun, npx, dlx, bunx, chained
      commands)
- [ ] M2.2 Registry checks (existence, age, downloads, typosquat, hallucination list,
      maintainer, provenance, deprecation)
- [ ] M2.3 Tarball checks via analyzer (install scripts, capabilities, obfuscation)
- [ ] M2.4 Policy engine and config file. Decision is `allow`, `ask`, or `deny`, with
      reasons
- [ ] M2.5 CLI: `depward check <spec...>`, `depward check --command "<shell>"`
- [ ] M2.6 Claude Code PreToolUse hook adapter (`depward hook claude`)
- [ ] M2.7 `@depward/mcp` with the `check_packages` and `check_install_command` tools
- [ ] M2.8 Docs site pages for setup in Claude Code, Cursor, and Codex CLI. Only document
      adapters that actually exist
- [ ] M2.9 Data files: `data/popular-packages.json`, `data/hallucinated-names.json`,
      with source and update script documented

**Definition of done:**
- The hook blocks a fixture "hallucinated" package and a fixture package that is 2 days
  old.
- Commands that install popular, stable packages are allowed.
- A warm-cache p95 check completes in under 1.5 s and a cold check in under 5 s. This
  is measured in a benchmark script.
- The false-positive rate on the top 1,000 packages' latest versions is under 1% `deny`
  and under 5% `ask`. The live benchmark result is recorded in `docs/benchmarks.md`.

---

## Phase 3 — `@depward/diff`: behavioral diff between versions (idea #3) → release 0.2

- [ ] M3.1 `diffPackages(a, b)` computes the capability delta, file delta, script delta,
      dependency delta, and publisher/provenance delta
- [ ] M3.2 Lockfile mode: `depward diff --lockfile [--base <ref>]`. Run with bounded
      concurrency
- [ ] M3.3 Risk scoring and `--fail-on <severity>`
- [ ] M3.4 Markdown PR comment (collapsible per package) and SARIF output
- [ ] M3.5 GitHub Action in `action/`. It posts or updates one sticky comment and
      uploads SARIF
- [ ] M3.6 The gate uses diff automatically when the requested package is already in the
      lockfile (the update path)
- [ ] M3.7 MCP tool `diff_versions`

**Definition of done:**
- Synthetic replays of three documented attack patterns are flagged as `high` or above:
  1. a new `postinstall` that downloads and runs code;
  2. a new environment-token read plus a network send;
  3. a new obfuscated blob in a patch release.
- 50 real patch or minor updates of popular packages produce no `high` findings, or each
  one is reviewed and justified.

---

## Phase 4 — `@depward/caps`: per-package capabilities (idea #1) → release 0.3

- [ ] M4.0 **Spike (time-boxed, 3 days):** prove `module.registerHooks` can give each
      importing package its own wrapped builtin, for both ESM and CJS. Measure
      overhead. Write the result as an ADR. Stop and report if it isn't feasible
- [ ] M4.1 `depward caps scan` writes `capabilities.lock.json` using static analysis
- [ ] M4.2 `depward caps check` in CI fails on new capabilities that haven't been
      approved. `depward caps approve <pkg>` approves them
- [ ] M4.3 Runtime `observe` mode: `node --import @depward/caps/register`, which logs
      capability use attributed to each package
- [ ] M4.4 Runtime `enforce` mode, with documented limitations (this is not a sandbox)

**Definition of done:** the caps lockfile round-trips. Runtime attribution is correct on
an Express + Prisma-like fixture app, with overhead under 5% on a request benchmark.
