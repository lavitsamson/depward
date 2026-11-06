# Finding ID catalog

Finding IDs are stable public API. Every ID emitted anywhere must have an entry here.
Format: `### <id>`, then default severity, which package emits it, what it means, how to
fix or suppress it, and false-positive notes.

<!-- Claude Code: add entries as you implement rules. See specs/analyzer.md, gate.md, diff.md. -->

### unsupported-lockfile

- **Default severity:** info
- **Emitted by:** `@depward/core` (`parseLockfile`)
- **Meaning:** the lockfile was recognized but its format can't be read, so none of its
  dependencies were checked. Formats: npm `lockfileVersion` 1, pnpm lockfiles older
  than 6.0 (or newer than 9.x), and the binary `bun.lockb`. `package` is the lockfile path.
- **Fix:** upgrade the lockfile. Run npm 7 or newer, pnpm 8 or newer, or
  `bun install --save-text-lockfile`.
- **False positives:** none. It is informational, and it means depward saw nothing.
