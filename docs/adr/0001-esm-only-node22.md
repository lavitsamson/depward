# 0001 — ESM-only, Node >= 22.15, pnpm workspace toolchain

- Status: accepted
- Date: 2026-11-02

## Context

depward is a new set of packages with no existing CommonJS consumers. Phase 4
(`@depward/caps`) needs synchronous, in-thread module hooks (`module.registerHooks`),
which first shipped in Node 22.15. depward is a security tool, so its own toolchain and
dependency graph must stay small and auditable.

## Decision

- Publish **ESM only**. Each package has `"type": "module"` and an `exports` map with
  `types` and `default` conditions. There is no CommonJS build.
- Require **Node >= 22.15** (`engines.node`). CI tests Node 22 and 24 on Linux, macOS,
  and Windows.
- TypeScript in strict mode with `erasableSyntaxOnly`, `verbatimModuleSyntax`, and
  `isolatedDeclarations` (for package sources). Source files import each other with
  `.ts` extensions.
- Build with tsdown, test with vitest, and lint with oxlint plus `tsc --noEmit`. Check
  published packages with publint and attw (`--profile esm-only`).
- Inside the workspace, each package's `exports` has a custom `@depward/source`
  condition that points at `src/index.ts`. TypeScript (`customConditions`), vitest, and
  `pnpm depward` use it, so nothing needs a build before typechecking, testing, or
  running the CLI from source. Published consumers never set this condition.
- Use pnpm 12 (`packageManager`). pnpm 11 replaced `onlyBuiltDependencies` with
  `allowBuilds`, so "no dependency may run build scripts" is expressed as
  `allowBuilds: {}` plus `strictDepBuilds: true` in `pnpm-workspace.yaml`, together with
  `ignoreScripts: true` and `minimumReleaseAge: 10080` (7 days, in minutes).

## Consequences

- CommonJS consumers must use `await import()`. attw's CJS rows are expected to show
  "ESM (dynamic import only)" and are ignored by the `esm-only` profile.
- Running `.ts` source directly relies on Node's built-in type stripping, which is on
  by default from Node 22.18. On 22.15–22.17, developers need
  `--experimental-strip-types`. Published `dist/` output is unaffected.
- The `VERSION` constant in each `src/index.ts` is kept in sync with package.json by
  `scripts/sync-versions.ts`, which runs after `changeset version`. A unit test in each
  package catches drift.
