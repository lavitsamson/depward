# data/

Checked-in data files used by `@depward/gate`. How they're built and why: ADR 0003
(`docs/adr/0003-popular-packages-data-source.md`). How to add entries: `CONTRIBUTING.md`.

| File | Contents | License |
|---|---|---|
| `popular-packages.json` | About 10,000 popular npm package names with one week of download counts. Used by `typosquat-suspect`. Regenerate with `node scripts/update-popular.ts` | CC BY-SA 4.0 |
| `hallucinated-names.json` | Package names that AI models are publicly documented to have invented. Used by `known-hallucinated-name`. Curated by hand | MIT, like the rest of the repo |

## Attribution

The selection of names in `popular-packages.json` is derived from
[ecosyste.ms](https://ecosyste.ms) package data, licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The download counts
come from the npm download-counts API (<https://api.npmjs.org>). If you redistribute
or adapt `popular-packages.json`, keep this attribution and the CC BY-SA 4.0 license.

The rest of this repository, including the code that reads these files, is MIT-licensed
(see `LICENSE`).
