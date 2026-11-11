# Benchmarks and reviews

Results of the live checks named in each phase's definition of done. Re-run with
`pnpm test:live` (Phase 1) and `pnpm bench:gate` / `pnpm bench:fp` (Phase 2).

## Phase 1: analyzer on 20 popular packages (2026-11-07)

Test: `test/live/popular-packages.test.ts`. Each tarball is downloaded from
registry.npmjs.org, integrity-checked, read in memory, and analyzed. Nothing is installed
or executed. The test pins the versions below and fails if the set of medium-or-higher
signals changes, so any change gets a new review.

Machine: Windows 11 laptop, Node 24.21. Time is `analyzePackage` only (no download).

| Package | Unpacked | Time | Medium or higher | Review |
|---|---:|---:|---|---|
| lodash@4.18.1 | 1.41 MB | 206 ms | none | — |
| react@19.3.1 | 0.18 MB | 24 ms | none | — |
| express@5.3.0 | 0.08 MB | 21 ms | none | — |
| axios@1.21.0 | 2.22 MB | 238 ms | none | — |
| chalk@6.0.1 | 0.06 MB | 7 ms | none | — |
| commander@15.1.0 | 0.21 MB | 18 ms | none | — |
| debug@4.4.3 | 0.04 MB | 4 ms | high `env-sensitive-read` | Benign. `Object.keys(process.env)` filtered to `DEBUG_*` options. |
| semver@7.8.6 | 0.12 MB | 15 ms | none | — |
| typescript@7.0.2 | 2.50 MB | 120 ms | none | — |
| esbuild@0.28.2 | 0.15 MB | 21 ms | high `env-sensitive-read`, high `install-script-network`, medium `install-script` | Correct. The postinstall may download the platform binary from the registry. The env read is `{ ...process.env }` passed to a child `npm install`. |
| sharp@0.35.5 | 0.96 MB | 35 ms | high `env-sensitive-read` | Benign. Copies `process.env` for a child process. |
| webpack@5.112.2 | 14.13 MB | 1,408 ms | high `env-sensitive-read` | Benign. `DotenvPlugin` copies and lists `process.env` to expand `.env` files. |
| ws@8.22.1 | 0.15 MB | 13 ms | none | — |
| uuid@14.0.3 | 0.07 MB | 9 ms | none | — |
| dotenv@18.0.9 | 0.05 MB | 5 ms | high `env-sensitive-read` | Benign. Merges parsed values with `process.env` (minified). |
| yargs@18.2.0 | 0.24 MB | 21 ms | none | — |
| node-fetch@3.3.2 | 0.11 MB | 9 ms | none | — |
| supports-color@11.0.0 | 0.01 MB | 2 ms | none | — |
| cross-spawn@7.0.6 | 0.02 MB | 3 ms | none | — |
| ci-info@4.4.0 | 0.03 MB | 2 ms | none | — |

**Criticals: none.** Every package under 1 MB took under 40 ms. The largest (webpack,
14 MB, 846 JS files) took 1.4 s.

### Tuning made during this review

The first run gave **esbuild a critical `env-exfil-pattern`**, a false positive. It had
two causes, both fixed (see `docs/specs/analyzer.md` § Implementation clarifications):

1. The spec's case-insensitive `NPM_` matched npm's own lowercase variables
   (`npm_config_user_agent`, also sharp's `npm_package_config_*`). Vendor prefixes now
   match only uppercase, at the start of the name. Secret words (`TOKEN`, `SECRET`,
   `KEY`, `PASSWORD`) still match in any case, so `npm_config__authToken` is still caught.
2. `env-exfil-pattern` fired whenever one file had both a sensitive read and any network
   use. It now requires the sensitive value to flow into a network call (directly,
   through variables, or through a request/socket object). The synthetic token-stealer
   replay and nine inline exfil shapes are still `critical`.

### Open question for Phase 2 (gate)

Five of the 20 packages get `high` `env-sensitive-read` only because they **enumerate**
`process.env` (spread or `Object.keys`). The spec treats enumeration as sensitive, and
the detection is correct, but it is benign in every case here. If the gate maps `high`
to `ask`, 25% of this sample would prompt. Options: lower the default severity of
enumeration-only evidence to `medium`, or let the policy treat `env-sensitive-read`
without `env-exfil-pattern` as `allow`. The top-1,000 benchmark in Phase 2 should decide.

## Phase 2: gate latency (2026-11-11)

Script: `pnpm bench:gate` (`scripts/bench-gate.ts`). Each install command is checked the
way one `depward hook claude` call checks it: a fresh registry client over the disk
cache, with analysis results cached as well (ADR 0005). **Cold** uses an empty cache
per command, so every packument, download count, and tarball comes from the network.
**Warm** is 5 runs per command over the cache the cold run left. Times cover
`checkCommand` only. Process start and imports (about 65 ms) come on top.

Machine: Windows 11 laptop, Node 24.21, home broadband.

| Command | Cold | Warm p50 | Action |
|---|---:|---:|---|
| `npm install lodash` | 1,267 ms | 4 ms | allow |
| `npm i express` | 173 ms | 8 ms | allow |
| `pnpm add react react-dom` | 1,636 ms | 94 ms | allow |
| `npm install --save-dev typescript` | 613 ms | 100 ms | allow |
| `yarn add axios` | 394 ms | 10 ms | ask |
| `pnpm add -D vitest` | 633 ms | 15 ms | ask |
| `npm i zod` | 627 ms | 27 ms | allow |
| `npm install chalk commander` | 192 ms | 8 ms | ask |
| `bun add dayjs` | 242 ms | 5 ms | allow |
| `npm i -D eslint prettier` | 2,804 ms | 26 ms | ask |
| `pnpm add uuid nanoid` | 116 ms | 7 ms | allow |
| `npm install dotenv` | 135 ms | 5 ms | ask |
| `npx prettier --write .` | 2,455 ms | 7 ms | ask |
| `npm i ws` | 116 ms | 6 ms | ask |
| `pnpm add -D @types/node` | 392 ms | 63 ms | allow |

**Cold: p50 394 ms, p95 2,804 ms** (target < 5 s). **Warm: p50 9 ms, p95 100 ms, max
130 ms** (target < 1.5 s). The asks are all `version-too-new` (see below), except
vitest's `fs-sensitive-path`.

Before the analysis cache, warm p95 was 2,610 ms: every call re-analyzed prettier
(2–5 s), react-dom (1.6 s), and eslint (0.8 s) from the cached tarball.

## Phase 2: false positives on the top 1,000 packages (2026-11-11)

Script: `pnpm bench:fp` (`scripts/bench-fp.ts`). Each of the 1,000 most-downloaded
packages in `data/popular-packages.json` (snapshot 2026-11-09) is checked as
`depward check <name>` (the latest version) with the default config. api.npmjs.org
rate-limits a 1,000-package burst, so the script retries HTTP 429 with backoff; a real
agent command checks only a few packages.

| Result | Packages | Target |
|---|---:|---|
| deny | 0 (0.0%) | < 1% |
| ask, excluding cooldown-only | 9 (0.9%) | < 5% |
| ask, cooldown only (`version-too-new`) | 124 (12.4%) | reported separately |
| allow | 867 (86.7%) | |

Cooldown asks aren't false positives: the version really is younger than 7 days, and
the message names the older version to use instead. The Definition of done was amended
to count them separately (approved 2026-11-11).

The 9 other asks, reviewed:

| Package | Cause | Review |
|---|---|---|
| tslib@2.9.1 | `publisher-changed` | Published 12 days ago by `microsoft1es` after six releases by `typescript-bot`. Correct by the rule: this is exactly what a takeover looks like from the registry. Benign (an internal release-account change at Microsoft), which only a human can confirm. |
| esbuild@0.28.2 | `install-script-network` | Correct (reviewed in Phase 1): the postinstall may download the platform binary. |
| core-js@3.51.0 | `install-script-network` | Conservative: the postinstall is inline `node -e "try{require('./postinstall')}catch(e){}"`, which the rule treats as possibly networked because inline code isn't followed. Benign. |
| @aws-sdk/credential-provider-login, @smithy/core | `fs-sensitive-path` | Correct and expected: AWS SDK config loaders build `~/.aws` paths. |
| pnpm, vite, vitest, napi-postinstall | `fs-sensitive-path` | Each references `.npmrc` (pnpm's bundled config reader, vite and vitest bundles, napi-postinstall's constants) to read registry config. Benign. |

Four of these also have `version-too-new`.

### Tuning made during this review

The first clean run had **182 asks (18.2%)**: 117 cooldown, 63 `publisher-changed`, and
8 others. Of the 63, **46 were packages that moved to npm trusted publishing**: the
publisher becomes `GitHub Actions <npm-oidc-no-reply@github.com>`, and the registry adds
`_npmUser.trustedPublisher` and a provenance attestation. 16 of the other 17 were
versions published more than 90 days ago (wrappy@1.0.2 in 2016, concat-map@0.0.2). Both
are now exempt (approved 2026-11-11, `docs/specs/gate.md` § Registry checks). A person
publishing after OIDC releases is still flagged, and a "GitHub Actions" name without the
registry's `trustedPublisher` record proves nothing.
