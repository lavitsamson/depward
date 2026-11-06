# Lockfile fixtures

The same small project locked by each package manager. It covers a registry package, a
scoped package, nested duplicate versions (`ms@2.0.0` under `debug`), an `npm:` alias,
dev and optional dependencies, a GitHub dependency, a tarball URL, `file:`, and a
workspace.

| Fixture | Origin |
|---|---|
| `npm/package-lock.json` | Generated: npm 11.19, `--package-lock-only --ignore-scripts` |
| `pnpm-v9/pnpm-lock.yaml` | Generated: pnpm 12.7, `--lockfile-only --ignore-scripts` |
| `yarn-v1/yarn.lock` | Generated: yarn 1.22.19, `--ignore-scripts` |
| `yarn-berry/yarn.lock` | Generated: yarn 4.9.2, `--mode=update-lockfile`, scripts disabled |
| `pnpm-v11-env/pnpm-lock.yaml` | Trimmed from depward's own pnpm 12 lockfile: an env document (pnpm itself) plus the project document |
| `pnpm-v6/pnpm-lock.yaml` | Hand-written in the pnpm 8 (v6.0) layout, checked against vite v4.5.0's lockfile |
| `bun/bun.lock` | Hand-written from the tuple layouts in Bun's `src/install/lockfile/bun.lock.rs` |

Lockfiles contain only metadata (names, versions, URLs, hashes); no package code.
