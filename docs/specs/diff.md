# Spec: @depward/diff

Catches malicious *updates* to packages you already trust. These attacks often arrive
before any CVE or advisory exists. Diff compares what version A could do with what
version B can do.

## API

```ts
function diffPackages(a: PackageProfile, b: PackageProfile, metaA: VersionMeta, metaB: VersionMeta): PackageDiff;
function diffLockfile(opts: { cwd: string; base?: string /* git ref */; head?: string }): Promise<LockfileDiffReport>;

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
| `diff-new-capability` | medium; **high** for `child_process`, `dynamic_code`, `native_addon` | capability in B and not in A |
| `diff-new-network-in-non-network-pkg` | high | A had no `net` capability, B does |
| `diff-new-sensitive-env` | high | new sensitive env keys, or new env enumeration |
| `diff-new-endpoint` | medium | new hardcoded endpoint; **high** if it's a raw IP |
| `diff-new-obfuscation` | critical | an `obfuscation` or `encoded-payload` signal appears in B and not in A |
| `diff-new-dependency` | low; **high** if the new dependency is itself young (`package-too-new`) | |
| `diff-publisher-changed` | high | the version was published by an account that didn't publish recent versions |
| `diff-provenance-dropped` | high | |
| `diff-semver-mismatch` | medium | a patch bump that adds a capability or install script |
| `diff-dist-only-change` | medium | built files changed substantially but the repository's source tag is missing (best-effort; later) |

**Escalation:** two or more `high` findings in one package → `critical`.

## Lockfile mode

1. Read the base lockfile at `--base` (default: merge-base with `origin/HEAD`), and the
   head lockfile from the working tree.
2. Run `diffLockfiles` from core. Only changed and added packages are analyzed. Added
   packages go through gate's registry checks plus the analyzer, because they have no
   "A" side.
3. Bounded concurrency (default 8). The tarball cache is shared.
4. Output: a report grouped by risk, with collapsed sections for low-risk changes.

## CLI

```
depward diff <name> <fromVersion> <toVersion>
depward diff --lockfile [--base <ref>] [--format markdown|sarif|json|terminal] [--fail-on high]
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
