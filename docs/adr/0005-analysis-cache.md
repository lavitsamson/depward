# 0005 — Cache analysis results by tarball integrity

- Status: accepted
- Date: 2026-11-11

## Context

Phase 2 requires a warm-cache p95 check under 1.5 s. The disk cache already keeps
tarballs (keyed by integrity), but every check analyzed them again. Analysis dominates
the cost: prettier@3.10.0 untars in about 0.1 s and analyzes in 2–5 s, react-dom in
about 1.6 s, and eslint and zod in about 0.8–0.9 s. The first latency benchmark had a
warm p95 of 2.6 s. Each hook call is a new process, so an in-memory cache doesn't help.

## Decision

`checkTarball` takes an optional `analysisCache` (a core `Cache`). The CLI, the Claude
Code hook, and the MCP server pass the same disk cache the registry client uses
(namespace `analysis`). Library callers get no cache unless they pass one.

- **Key:** `analyzer@<VERSION>:r<ANALYSIS_REVISION>:<strongest SRI hash>:<limits JSON>`.
  The analyzer's new `ANALYSIS_REVISION` export is bumped in any change that can alter a
  profile, so development builds (all `0.0.0`) don't serve stale results. Versions with
  only a sha1 `shasum` are never cached.
- **Value:** the `PackageProfile` as JSON (16–200 KB for the packages measured). Findings
  are recomputed from it with `profileFindings` and reported under the requested name
  and version, as before.
- **Only successes are stored:** an analysis of bytes that passed integrity
  verification. Network errors, integrity mismatches, and unsafe archives are never
  cached, so a transient failure can't stick and a crafted archive is re-examined.
- **A cache problem never changes a decision:** an unreadable, malformed, or
  wrong-shaped entry is ignored and the package is analyzed again; a failed write is
  ignored.
- A hit skips the tarball download too.

## Consequences

- Warm checks of large packages drop from seconds to a few milliseconds (see
  `docs/benchmarks.md`).
- The cache directory becomes more security-relevant. A tarball can be re-verified
  against its hash on read, but a cached analysis can't: anyone who can write to the
  user's cache directory could plant a clean profile for a malicious version. That
  attacker can already change the user's dotfiles and npm config, so this doesn't add a
  new trust boundary, but it is documented here. `DEPWARD_CACHE_DIR` should not point
  at a directory other users can write to.
- Entries never expire. The key changes with every analyzer release or revision bump,
  so old entries just stop being read. Cache pruning is out of scope for now.
- Forgetting to bump `ANALYSIS_REVISION` during development serves stale results only
  until the next release, because `VERSION` is in the key.
