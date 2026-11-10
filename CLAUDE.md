# CLAUDE.md — depward

This file is read at the start of every Claude Code session. Keep it short and current.
Detailed plans live in `docs/`. Read the relevant spec before starting any task.

## What this project is

`depward` is a set of open-source tools that protect JavaScript projects from risky
dependencies. It is especially aimed at AI coding agents, which install packages with no
human watching. The tools never run package code. They read registry metadata and
statically analyze tarballs.

| Package | Purpose | Phase | Spec |
|---|---|---|---|
| `@depward/core` | Registry client, tarball reader, lockfile parsers, cache, config, reporters | 1 | `docs/specs/core.md` |
| `@depward/analyzer` | Static capability and risk-signal extraction from a package tarball | 1 | `docs/specs/analyzer.md` |
| `@depward/gate` | Admission check before install: allow / ask / deny, plus agent hook adapters | 2 | `docs/specs/gate.md` |
| `@depward/diff` | Behavioral diff between two versions, or across a lockfile change | 3 | `docs/specs/diff.md` |
| `@depward/mcp` | MCP server that exposes gate and diff to agents | 2–3 | `docs/specs/gate.md` §MCP |
| `depward` | The CLI binary. A thin wrapper over the packages above | 2 | `docs/specs/gate.md` §CLI |
| `@depward/caps` | Per-package capability lockfile and runtime attribution | 4 | `docs/specs/caps.md` |

The HTML-to-PDF product formerly planned as Phase 5 lives in a separate repository
(`docs/adr/0002-pdf-separate-repo.md`). Do not add PDF code here.

Build order and milestones: `docs/ROADMAP.md`. **Do not start a phase until the previous
phase's "Definition of done" is met**, unless the user says otherwise.

## Commands

```bash
pnpm install --frozen-lockfile   # install (scripts are disabled, see .npmrc)
pnpm build                       # tsdown build of all packages
pnpm test                        # vitest, offline, uses fixtures only
pnpm test:live                   # opt-in tests that hit the real npm registry
pnpm lint                        # oxlint + tsc --noEmit
pnpm check:publish               # publint + attw for every package
pnpm depward -- <args>           # run the local CLI from source
```

Run `pnpm lint && pnpm test` before you say a task is finished. If something fails and
you can't fix it, say so plainly. Never weaken or delete a test to make it pass.

## Tech stack (decided; don't change without an ADR in `docs/adr/`)

- TypeScript, strict mode, `erasableSyntaxOnly`, `verbatimModuleSyntax`.
- **ESM-only**, Node **>= 22.15** (needed for `module.registerHooks` in Phase 4).
- pnpm workspaces. Build with **tsdown**. Test with **vitest**. Lint with **oxlint**.
- Releases use **changesets**, and are published **from CI only** with npm trusted
  publishing (OIDC) and provenance.
- CLI argument parsing uses `node:util` `parseArgs`. Do not add a CLI framework.
- HTTP uses global `fetch`. Do not add an HTTP client.

## Our own supply chain (critical: this is a security tool and will be a target)

1. **Runtime dependencies are allowlisted.** Approved:
   - `acorn` and `acorn-walk` (analyzer)
   - `semver` (core)
   - `yaml` (core, for pnpm and yarn-berry lockfiles)
   - `@modelcontextprotocol/server` (with its `@modelcontextprotocol/core`) and `zod`
     (**only** in `@depward/mcp`; SDK v2, ADR 0004)

   Adding any other runtime dependency needs an ADR and the user's approval. Prefer
   writing 50 lines of code over adding a dependency. Dev dependencies are freer, but
   pin exact versions.
2. Write small internals ourselves instead of adding packages: the tar reader (ustar plus
   pax headers, in memory), Levenshtein distance, entropy, and the command-line tokenizer.
3. Install scripts are off: `ignoreScripts: true` in `pnpm-workspace.yaml` (and
   `ignore-scripts=true` in `.npmrc` for npm users). `minimumReleaseAge` is 10080 minutes
   (7 days). `allowBuilds` is empty with `strictDepBuilds: true`; pnpm 11 replaced
   `onlyBuiltDependencies` with `allowBuilds` (ADR 0001).
4. Pin GitHub Actions by full commit SHA. CI uses least-privilege `permissions:`.
5. CI dogfoods the tool: it runs `depward diff --lockfile --base origin/main` on every PR.

## Hard safety rules for this codebase

- **Never execute package code.** No `npm install`, `require`, `import()`, or `vm` on
  analyzed packages. Only fetch tarballs with `fetch` and read them in memory.
- **Never write extracted package files to disk** outside the integrity-addressed cache,
  and never mark them executable. Reject tar entries with absolute paths, `..`, or
  symlinks pointing outside the package.
- **Never download real malware** to use as a test fixture. Build **synthetic, inert
  fixtures** that copy the *patterns* of known attacks. Example: code that reads
  `process.env.NPM_TOKEN` and passes it to `fetch("https://exfil.example.invalid")`.
  Use `.invalid` / `example.*` domains and RFC 5737 IP addresses only.
- Default tests are **offline**. Registry responses are recorded JSON in
  `fixtures/registry/`. Live tests are under `test/live/` and only run in `test:live`.
- Enforce limits everywhere: maximum tarball size (default 50 MB), maximum single file
  analyzed (5 MB; larger files produce an `oversized-file` signal), maximum files per
  package, and timeouts on every network call.
- Treat all package contents and registry metadata as untrusted data. Never interpolate
  them into shell commands. Strip ANSI escape codes and control characters before
  printing them in terminal or markdown output.

## Code conventions

- Pure functions in `src/`, I/O at the edges. Network and filesystem access go through
  interfaces in `@depward/core` (`RegistryClient`, `Cache`) so tests can inject fakes.
- Every finding is a `Finding` object (`id`, `severity`, `package`, `version`, `message`,
  `evidence[]`, `docsUrl`). Finding IDs are **stable public API**. Their catalog is
  `docs/findings.md`. Add an entry there whenever you add a new ID.
- Output must be deterministic: sort findings by severity, then package, then id. Use
  snapshot tests for reporters.
- Errors are typed (`DepwardError` with a `code`). Never throw strings.
- Public exports are documented with TSDoc. Each package has a README with one runnable
  example.
- Keep files under about 400 lines. Split by responsibility.

## Workflow expectations

- Work milestone by milestone, following `docs/ROADMAP.md`. At the start of a task,
  restate which milestone and acceptance criteria you are working toward.
- Write tests first for parsers and detectors: lockfiles, command tokenizer, tar reader,
  and each analyzer rule.
- When a spec is ambiguous or wrong, propose an edit to the spec file and wait for the
  user's approval before diverging from it.
- Things that change after your knowledge cutoff (the Claude Code hook schema, MCP SDK
  API, npm registry endpoints, Node APIs): **check the current official docs before
  implementing**, and record the doc URL in a code comment.
- Record decisions in `docs/adr/NNNN-title.md` (context, decision, consequences).
- Update `docs/ROADMAP.md` checkboxes as milestones complete.
