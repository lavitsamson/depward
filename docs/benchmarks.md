# Benchmarks and reviews

Results of the live checks named in each phase's definition of done. Re-run with
`pnpm test:live`.

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
