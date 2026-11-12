# depward diff — GitHub Action

Checks the npm dependency changes in a pull request. For every updated package it compares
what the new version can do with what the old one could (new install scripts, network
use, secret reads, endpoints, obfuscation, publisher and provenance changes). New packages
get the registry and tarball checks of `depward check`. Package code is never run: the
Action reads registry metadata and analyzes tarballs in memory.

It keeps **one** pull request comment up to date, uploads the findings to code scanning
as SARIF, and fails the step when a package's risk reaches `fail-on`.

## Usage

```yaml
name: depward
on: pull_request

permissions:
  contents: read

jobs:
  diff:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # the sticky comment
      security-events: write # the SARIF upload
    steps:
      - uses: actions/checkout@<full commit SHA> # pin by SHA
        with:
          persist-credentials: false
          fetch-depth: 0 # the merge-base with the base branch needs history
      - uses: lavitsamson/depward/action@<full commit SHA>
        with:
          fail-on: high
```

Lockfiles are read from the checkout, so no `npm install` is needed (and none should run
before this step). Supported: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`,
`yarn.lock` (classic and berry), and `bun.lock`.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `fail-on` | `critical` | Fail when a changed package's risk reaches this level: `critical`, `high`, `medium`, `low`, `info` (any finding), or `none` |
| `comment` | `true` | Post or update the sticky PR comment |
| `sarif` | `true` | Upload SARIF to code scanning |
| `base` | the PR's base branch | Git ref to compare with. On `push`, the commit before the push |
| `github-token` | `${{ github.token }}` | Token for the comment and the upload |

The step also fails when a registry lookup failed, because part of the change went
unchecked. The project's `depward.config.json` (or the `depward` key of `package.json`)
applies: `policy` overrides set to `allow` and the `allow` list keep findings visible but
uncounted, and a package on the `deny` list is `critical`.

## Outputs

| Output | Meaning |
|---|---|
| `risk` | The highest package risk |
| `changes` | Number of package changes checked |
| `failed` | `true` when the step failed |
| `comment-url` | The sticky comment, when one was posted or updated |
| `sarif-file` | The SARIF file under `RUNNER_TEMP`, for `github/codeql-action/upload-sarif` or an artifact |

## Permissions and forks

- `contents: read` to read the repository.
- `pull-requests: write` for the comment. Without it, the report goes to the job summary
  and a warning says so.
- `security-events: write` for the SARIF upload, which also needs code scanning to be
  available for the repository. Without it, the upload is skipped with a warning.

On a `pull_request` from a fork, GitHub gives the job a read-only token. The Action
doesn't try to comment or upload: it writes the report to the job summary. Don't switch
to `pull_request_target` to get a write token. This step reads the PR's lockfiles, which
are safe to read, but a `pull_request_target` workflow that checks out fork code is a
common way to leak secrets.

The comment is found by a hidden marker (`<!-- depward-diff -->`) on a comment by a bot
account. When there are no dependency changes, no new comment is posted, but an
existing one is updated.

## Building

The Action runs from `dist/index.mjs`, a single bundled file committed to the repository.
After changing the sources (here or in `packages/`), run `pnpm build:action` and commit
`dist/`. CI fails when the committed bundle is stale. `dist/THIRD_PARTY_LICENSES.txt`
lists the bundled packages' licenses. `dist/data/` holds the data files (see
`data/README.md` for their licenses).
