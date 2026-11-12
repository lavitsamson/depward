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
  source changed, run the gate's registry and tarball checks. A change to the dev or
  optional flag only is not checked.
- **Sources:** new git, tarball-URL, and other non-npm entries emit `non-registry-source`.
  `file`, `link`, `workspace`, and `bundled` entries are skipped (listed as skipped).
- **Young dependencies:** `diff-new-dependency` is `high` when the new dependency's own
  entry got `package-too-new`. New packages are checked before updates for this reason.
- **Integrity:** for every new or updated registry entry, `lockfile-integrity-mismatch`
  (critical) fires when the lockfile's integrity disagrees with the registry's `dist`
  for that version. This catches a lockfile whose `resolved` URL was redirected to
  another tarball.
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

## Markdown report format

```
## depward: 3 dependency changes, 1 needs review
| Risk | Package | Change | Why |
|---|---|---|---|
| 🔴 critical | foo | 2.1.3 → 2.1.4 | new postinstall · new network · publisher changed |
<details><summary>foo 2.1.3 → 2.1.4</summary> evidence with file:line and short snippets </details>
```

Snippets are capped at 200 characters, with control characters and HTML escaped.

## Tests

- Unit tests for each delta type, using pairs of synthetic profiles.
- The attack-replay fixture pairs (clean v1 → malicious v1.0.1) from the analyzer spec
  must produce `high` or above.
- Live: 50 real recent patch/minor updates of popular packages. Record the noise level
  in `docs/benchmarks.md`.
