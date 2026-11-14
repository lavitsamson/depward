# Spec: @depward/diff

Catches malicious *updates* to packages you already trust. These attacks often arrive
before any CVE or advisory exists. Diff compares what version A could do with what
version B can do.

## API

```ts
function diffPackages(
  a: PackageProfile, b: PackageProfile, metaA: VersionMeta, metaB: VersionMeta,
  ctx?: { packument?: Packument; now?: number },
): PackageDiff;
function diffLockfile(opts: { cwd: string; base?: string /* git ref */; head?: string; registry: RegistryClient; … }): Promise<LockfileDiffReport>;
function diffVersions(name: string, from: string, to: string, opts: { registry: RegistryClient; … }): Promise<PackageChangeResult>;

interface PackageDiff {
  name: string; from: string; to: string;
  capabilityDelta: { added: Capability[]; removed: Capability[] };
  signalDelta: { added: Signal[]; removed: Signal[] };
  scriptDelta: Record<string, { from?: string; to?: string }>;
  dependencyDelta: { added: string[]; removed: string[]; changed: string[] };
  fileDelta: { added: string[]; removed: string[]; changedLarge: string[] };
  endpointDelta: { added: string[] };
  envKeyDelta: { added: string[] };
  publisherDelta?: { from: string; to: string };
  provenanceDelta?: "dropped" | "added";
  findings: Finding[];
  risk: Severity;
}
```

## Findings

| ID | Default severity | Rule |
|---|---|---|
| `diff-new-install-script` | high | B has an install script that A didn't have, or it changed |
| `diff-new-capability` | medium; **high** for `child_process`, `dynamic_code`, `native_addon` | capability in B and not in A (except `net`, see the next row) |
| `diff-new-network-in-non-network-pkg` | high | A had no `net` capability, B does. Replaces `diff-new-capability` for `net`, so one change counts once toward escalation |
| `diff-new-sensitive-env` | high | new sensitive env keys, or new env enumeration |
| `diff-new-endpoint` | medium | new hardcoded endpoint; **high** if it's a raw IP |
| `diff-new-obfuscation` | critical | an `obfuscation` or `encoded-payload` signal appears in B and not in A |
| `diff-new-dependency` | low; **high** if the new dependency is itself young (`package-too-new`) | |
| `diff-publisher-changed` | high | the version was published by an account that didn't publish recent versions |
| `diff-provenance-dropped` | high | |
| `diff-semver-mismatch` | medium | a patch bump that adds a capability or install script |
| `diff-dist-only-change` | medium | built files changed substantially but the repository's source tag is missing (best-effort; later) |

**Escalation:** two or more `high` findings in one package → `critical`.

### Delta rules (clarified 2026-11-12)

- **Signals** are compared by `id` only. `signalDelta.added` holds every signal of B whose
  id A doesn't have, and `removed` is the reverse. Per-file keys would re-flag the same
  signal on every release of a bundled package, because chunk names such as
  `index.Di8au7q4.js` change each time.
- **Scripts** cover `preinstall`, `install`, `postinstall`, and `prepare`, taken from the
  profiles (so the implicit `node-gyp rebuild` counts). `diff-new-install-script` ignores
  `prepare`, because npm does not run it for registry installs.
- **Dependencies** come from the version metadata: `dependencies`,
  `optionalDependencies`, and `peerDependencies`, merged by name. `changed` means the
  range changed. `diffPackages` cannot see the registry, so it emits
  `diff-new-dependency` as `low`. Lockfile mode (M3.2) raises it to `high` when the new
  dependency is young.
- **`changedLarge`**: a file that is in both versions, has a different hash, and whose
  size changed by more than 50% or by more than 100 KB.
- **Sensitive env**: new keys that match the analyzer's `isSensitiveEnvKey`, or an
  `env-sensitive-read` "enumerates process.env" evidence in B when A had none.
- **Publisher**: `publisherDelta` records any change of `_npmUser.name` between A and B.
  The finding uses core's `publisherChange` when `ctx.packument` is given, so it follows
  the gate's exemptions: established maintainers, trusted publishing, and, with
  `ctx.now`, versions older than 90 days. Without a packument, the finding fires when
  the names differ and B is not a trusted publish.
- **Provenance** compares A with B directly: `dropped` if A had attestations and B has
  none.
- **Semver mismatch** applies when B is a patch bump of A (same major and minor, which
  includes `0.0.x` → `0.0.y`). Prerelease tags are ignored for this comparison.
- `diff-dist-only-change` is deferred and not emitted yet.

## Lockfile mode

1. Read the base lockfile at `--base` (default: merge-base with `origin/HEAD`), and the
   head lockfile from the working tree.
2. Run `diffLockfiles` from core. Only changed and added packages are analyzed. Added
   packages go through gate's registry checks plus the analyzer, because they have no
   "A" side.
3. Bounded concurrency (default 8). The tarball cache is shared.
4. Output: a report grouped by risk, with collapsed sections for low-risk changes.

### Lockfile rules (clarified 2026-11-12)

- **Base:** the base lockfiles are read at the merge-base of `HEAD` and `--base`
  (default `origin/HEAD`), so a base branch that has moved on doesn't show up as reverted
  changes. If `origin/HEAD` doesn't exist, it fails and asks for `--base`. `--head <ref>`
  reads the head lockfiles from a ref instead of the working tree.
- **Files:** every known lockfile name present in the directory, at the base or the
  head, is compared. A lockfile missing at the base makes all of its entries new.
- **Updates:** core's `diffLockfiles` reports a version bump as one removed and one
  added entry. Registry entries with the same name are paired into updates A → B. Each
  added version (lowest first) takes the highest unused removed version with the same
  major, otherwise the highest unused removed version. Added entries left over are new
  packages.
- **New packages**, and `changed` entries (same name@version) whose integrity or
  source changed, run the gate's registry and tarball checks. So do entries whose
  `resolved` changed while either side has no integrity (amended 2026-11-14: a hash on
  both sides pins the bytes; without one, a new URL can mean a new tarball). A change to
  the dev or optional flag only is not checked.
- **npm entries** with a semver version and a registry-style `/-/` tarball URL are
  registry entries even without integrity (amended 2026-11-14), so the source rule below
  applies to them.
- **Sources:** new git, tarball-URL, and other non-npm entries emit `non-registry-source`.
  `file`, `link`, `workspace`, and `bundled` entries are skipped (listed as skipped).
- **Young dependencies:** `diff-new-dependency` is `high` when the new dependency's own
  entry got `package-too-new`. New packages are checked before updates for this reason.
- **Integrity:** for every new or updated registry entry, `lockfile-integrity-mismatch`
  (critical) fires when the lockfile's integrity disagrees with the registry's `dist`
  for that version. This catches a lockfile whose `resolved` URL was redirected to
  another tarball.
- **Source (added 2026-11-14):** when no lockfile hash can be compared with the
  registry's (none recorded, or only algorithms the registry doesn't publish) and
  `resolved` is not served by the registry, `lockfile-untrusted-source` (critical)
  fires. "Served by the registry" means the origin of the version's `dist.tarball`, or
  `registry.npmjs.org`, `registry.npmjs.com`, or `registry.yarnpkg.com` over https.
  Without this rule, a `sha256-` hash of an attacker's tarball on another host passes
  the integrity rule (nothing to compare) and the package manager's own check.
- **Limits:** at most 1,000 packages to check (`LIMIT_EXCEEDED` above that). The same
  change in several lockfiles is checked once. Lookups that fail are reported per
  package and make the CLI exit 1.
- **Package code** is analyzed through the gate's tarball check, so the analysis cache
  (ADR 0005) is shared with `depward check`.

## Risk and `--fail-on` (decided 2026-11-12)

- **Package risk:** for an update, the highest finding severity, or `critical` when two
  or more findings are `high`. For a new, changed, or non-registry package, the highest
  finding severity (gate semantics, with no escalation). `info` when nothing counts.
- **Project config** (the same file `depward check` reads) is applied after the checks:
  - a finding whose ID the `policy` key sets to `allow` stays in the report as allowed
    (`allowedFindings`) but doesn't count toward risk. `ask` and `deny` overrides don't
    change diff risk;
  - a package on the `allow` list is reported, with every finding allowed;
  - a package version on the `deny` list gets the gate's `denylisted` finding, and its
    risk is `critical`.
- **`--fail-on <level>`:** `critical` (the default, the same as the Action's),
  `high`, `medium`, `low`, `info`, or `none`. The run fails when a package with at least
  one counted finding (or a deny-list match) has a risk at or above the level, so
  `--fail-on info` means "any finding".
- **Exit codes:** `0` below the threshold, `20` threshold reached (the same code as
  `depward check`'s deny), `1` error. A failed lookup is an error (`1`), because part of
  the change went unchecked, but a reached threshold wins over it: the change is
  blocked either way. The config's `onError` does not apply to diff.

## CLI

```
depward diff <name> <fromVersion> <toVersion> [--fail-on <level>]
depward diff --lockfile [--base <ref>] [--head <ref>] [--format markdown|sarif|json|terminal] [--fail-on <level>]
```

## GitHub Action (`action/`)

- A JavaScript action (`runs.using: node24` — verify that this runtime is currently
  supported by GitHub; otherwise use node20). It is bundled to a single file in
  `action/dist` and committed. A CI check verifies that `dist` is up to date.
- Inputs: `fail-on` (default `critical`), `comment` (default true), `sarif` (default
  true), `base`.
- Posts **one** sticky PR comment, identified by a hidden HTML marker, and updates it on
  each push. Uploads SARIF for code scanning.
- Required permissions are documented: `contents: read`, `pull-requests: write`,
  `security-events: write`.
- Must work on `pull_request` from forks in read-only mode. If it can't comment, it
  writes to the job summary instead.

### Action details (clarified 2026-11-12)

- **Runtime:** `node24`, a documented `runs.using` value (checked 2026-11-12). Bundled
  with tsdown to `action/dist/index.mjs`, with every dependency inlined. Core's lazy
  `createRequire` loader is swapped for an eager one in the bundle only. The data files
  are copied to `action/dist/data/`, and the licenses of the bundled packages go to
  `action/dist/THIRD_PARTY_LICENSES.txt`. The CI job `action-dist` rebuilds the bundle
  and fails when it differs.
- **No toolkit packages:** inputs, workflow commands, outputs, and the job summary are
  written by hand, and the REST calls use `fetch`. `@actions/*` are not runtime
  dependencies.
- **Extra input:** `github-token` (default `${{ github.token }}`). **Outputs:** `risk`,
  `changes`, `failed`, `comment-url`, `sarif-file`.
- **Base:** the `base` input, or `origin/<PR base branch>` on `pull_request`, or the
  event's `before` commit on `push`. Otherwise it fails and asks for `base`. The
  checkout needs `fetch-depth: 0`.
- **Sticky comment:** the first line is `<!-- depward-diff -->`. Only comments by a
  `Bot` account are updated, so a user who pastes the marker can't take over the
  comment. With no dependency changes, an existing comment is updated but no new one is
  created.
- **SARIF:** uploaded with `POST /repos/{owner}/{repo}/code-scanning/sarifs`, gzip and
  base64, using `GITHUB_SHA` and `GITHUB_REF` (`refs/pull/N/merge` on a PR). It is also
  written to `$RUNNER_TEMP/depward-diff.sarif`.
- **Forks and missing permissions:** on a fork PR, nothing is written through the API.
  A notice is shown and the report goes to the job summary. A 403 or 404 from the
  comment or upload gives a warning that names the missing permission (and the summary,
  for the comment). Any other API error fails the step.
- **Step result:** it fails (exit 1) when the risk reaches `fail-on` or a lookup
  failed, the same rule as the CLI's exit codes 20 and 1.

## Markdown report format

```
## depward: 3 dependency changes, 1 needs review
| Risk | Package | Change | Why |
|---|---|---|---|
| 🔴 critical | foo | 2.1.3 → 2.1.4 | new postinstall · new network · publisher changed |
<details><summary>foo 2.1.3 → 2.1.4</summary> evidence with file:line and short snippets </details>
```

Snippets are capped at 200 characters, with control characters and HTML escaped.

### Report details (clarified 2026-11-12)

- **Table:** one row per package with a non-`info` finding, a failed lookup, or a
  deny-list match, worst first. "Why" uses short labels for the diff IDs (other IDs as
  they are), at most four, then `+N more`. "Needs review" counts packages at `medium`
  or above, plus failed lookups.
- **Sections:** one `<details>` per table row. `high` and `critical` start open; lower
  risks start collapsed. Each shows the lockfile (and line), up to 5 evidence items per
  finding (`file:line`, snippet, detail), failed lookups, and config-allowed findings.
- **Quiet packages** (no counted findings) and **skipped** entries are listed in
  collapsed sections at the end.
- **Size:** output stays under 60,000 characters (a GitHub comment is capped at
  65,536). The table takes at most half of that; sections are added worst first until
  one doesn't fit. A note says how many rows and sections were left out.
- **Escaping:** every package-controlled string goes through core's `escapeMarkdown`.

## SARIF (clarified 2026-11-12)

Each result is located at its package's entry in the first lockfile it appears in, at
the head (npm `"node_modules/name"`, pnpm `name@version:`, yarn `name@range:` followed
by its version, bun `"name@version"`), so GitHub shows the alert on the PR's changed
lines. When the entry isn't found, line 1. Lockfile-level findings point at their
lockfile. Config-allowed findings are not included.

## Tests

- Unit tests for each delta type, using pairs of synthetic profiles.
- The attack-replay fixture pairs (clean v1 → malicious v1.0.1) from the analyzer spec
  must produce `high` or above.
- Live: 50 real recent patch/minor updates of popular packages. Record the noise level
  in `docs/benchmarks.md`.
