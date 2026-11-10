# 0003 — Data sources for popular and hallucinated package names

- Status: accepted (2026-11-09)
- Date: 2026-11-08

## Context

The gate's typosquat check (`typosquat-suspect`, M2.2) compares a requested name with
about 10,000 popular npm packages and their weekly download counts
(`data/popular-packages.json`). The `known-hallucinated-name` check needs a list of
names that AI models are known to invent (`data/hallucinated-names.json`).

npm has no endpoint that ranks packages by downloads. Its download-counts API
(<https://github.com/npm/registry/blob/main/docs/download-counts.md>) returns counts for
names you already know: bulk queries take at most 128 packages and don't accept scoped
names. The search API (`/-/v1/search`) ranks by relevance and returns at most 250 results
per page, so it can't produce a top-10,000 list reliably.

We considered these options:

1. **ecosyste.ms** (`GET https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?sort=downloads&order=desc`,
   <https://packages.ecosyste.ms/docs>). It ranks every npm package by last-month
   downloads, returns at most 1,000 rows per page, and allows 5,000 requests an hour
   anonymously. Its data is licensed CC BY-SA 4.0 (<https://ecosyste.ms>).
2. **A published list** such as the `npm-high-impact` package. That would mean a dev
   dependency, a list that refreshes on someone else's schedule, and ranking rules we
   don't control.
3. **Crawling the whole registry** (`replicate.npmjs.com`) and counting downloads for
   every package. This takes millions of requests, which is far too heavy for a data
   file we refresh monthly.

## Decision

- `scripts/update-popular.ts` takes the **candidate names** from ecosyste.ms (option 1),
  fetching 15% more than needed, then takes **weekly counts from npm's own
  download-counts API**: point totals for a fixed 7-day range ending yesterday (UTC),
  chosen once per run (or given with `--range`), because `last-week` rolls over at
  midnight. It uses bulk queries for unscoped names and one request per scoped name. It
  keeps the top `--limit` (default 10,000) by npm's weekly count.
- npm stays the authority for the numbers, so the file matches what `low-downloads`
  measures. ecosyste.ms only decides which names are considered.
- The file records its `snapshot` date, the `week` its counts cover, and both sources.
  Refresh it by hand about monthly and review the diff (one package per line).
- `data/hallucinated-names.json` is curated by hand. Every entry needs a public source
  URL that documents the name as AI-hallucinated. The process is in CONTRIBUTING.md. We
  don't import bulk research datasets of hallucinated names, such as the roughly
  205,000 names from Spracklen et al. (USENIX Security 2025). Many of those names are
  generic or are now legitimate packages, and an entry means `deny`.

## Consequences

- **Licensing (confirmed by the maintainer, 2026-11-09):** the ranking that chose the
  names comes from CC BY-SA 4.0 data. Package names and npm's download counts are
  facts, and the file contains no ecosyste.ms content beyond which names were selected,
  but we treat the file as CC BY-SA 4.0 regardless: it credits ecosyste.ms in `source`,
  declares `"license": "CC-BY-SA-4.0"`, and `data/README.md` says so. The code stays
  MIT; only this data file carries the share-alike license. If `@depward/gate` bundles
  the file (decided in M2.2), the package README must repeat the credit and license.
  **M2.2 (2026-11-10):** it does. The build copies both data files to
  `packages/gate/dist/data/` as separate JSON files, not inlined into the JavaScript
  bundle, so the license boundary stays at the file. The gate README repeats the credit.
- A refresh needs two third-party services and takes about 1.5 hours. Nearly half of
  the candidates are scoped and need one request each, and npm's download API returns
  429 after about 20 quick requests (with `retry-after: 0`). So the script is a
  deliberately polite client: requests are strictly sequential, at least 2 s apart with
  random jitter; each 429 doubles the gap (up to 30 s) and pauses 30 s or more (longer
  if `retry-after` asks for it), and the gap eases back only slowly. It retries network
  errors and checkpoints per date range to the OS temp dir. A rerun resumes where it stopped (pass
  the same `--range` on a later day).
- Packages that ecosyste.ms ranks below the cutoff but that npm counts higher can be
  missed. The 15% over-fetch keeps that to the margin.
- The seed list of hallucinated names is short (two documented npm cases). The
  `package-not-found` check covers names that were never registered. This list matters
  for names that someone registered later, including security-holding placeholders,
  both of which apply to the two seed entries.
