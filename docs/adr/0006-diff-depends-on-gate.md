# 0006 — `@depward/diff` depends on `@depward/gate`; the gate gets diff by injection

- Status: accepted
- Date: 2026-11-12

## Context

Lockfile mode (M3.2) checks packages that are new in a lockfile with the gate's
registry checks and analyzes every tarball through the gate's tarball check, which owns
the analysis cache (ADR 0005). M3.6 needs the reverse: when an agent asks to install a
package that is already in the lockfile, the gate should diff the update. Two packages
that import each other would be a cycle.

The publish-history helpers (`publisherChange`, `provenanceDrop`, …) that both need
were moved from gate to core in M3.1, so the pure `diffPackages` doesn't need the gate.

## Decision

- `@depward/diff` depends on `@depward/gate` and calls `checkPackage` and `checkTarball`
  directly from lockfile mode (`diffLockfile`, `diffVersions`).
- `@depward/gate` never imports `@depward/diff`. For M3.6 the gate takes an optional
  callback (for example `diffUpdate`) in its options. The CLI and the MCP server, which
  depend on both packages, pass `diffVersions`.

The alternative was to keep diff free of the gate and inject `checkAdded` and `analyze`
callbacks into `diffLockfile`. That puts two injection points on every caller of
lockfile mode instead of one optional point on the gate.

## Consequences

- Installing `@depward/diff` installs the gate and its bundled data files (the
  popular and hallucinated package lists).
- Lockfile mode shares the gate's analysis cache and finding semantics automatically.
- A library user of the gate who wants the update diff must wire the callback
  themselves; without it the gate behaves as in Phase 2.
