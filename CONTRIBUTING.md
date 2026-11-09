# Contributing to depward

Thanks for helping. Read [CLAUDE.md](CLAUDE.md) for the project rules: no package code is
ever executed, and test fixtures are synthetic. Before opening a PR, run:

```bash
pnpm install --frozen-lockfile
pnpm lint && pnpm test
```

Report security issues privately, as described in [SECURITY.md](SECURITY.md), not in a
public issue or PR.

## Adding a hallucinated package name

`data/hallucinated-names.json` lists package names that AI models are **publicly
documented** to have invented. The gate **denies** these names even if someone has
since registered them, so every entry needs evidence.

1. **Find a public source** that shows a model suggested the name and that the name
   didn't exist (or wasn't the real package) when it did. Good sources are security
   research posts, papers, and advisories. A screenshot of your own chat or a
   social-media post isn't enough on its own.
2. **Check the name.** It must be a valid npm name, it must not be in
   `data/popular-packages.json`, and the package it was confused with must exist.
3. **Add an entry**, keeping the list sorted by `name`:

   ```json
   {
     "name": "react-codeshift",
     "ecosystem": "npm",
     "firstSeen": "2025-10-17",
     "source": "https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands",
     "suggestion": "jscodeshift"
   }
   ```

   - `firstSeen`: the earliest date the source gives for the hallucination (`YYYY-MM-DD`).
   - `source`: an `https` URL. If the page has moved or gone, link to an archived copy
     (`web.archive.org`).
   - `suggestion`: the real package the agent most likely wanted. The gate shows it in
     its deny message, so the agent can correct itself.
4. **Run `pnpm test`.** `packages/gate/test/data.test.ts` validates the file.

Names that appear in documentation but were never published, and that no AI produced
(for example, a README that tells users to `npx` a package that doesn't exist), don't
belong here. The `package-not-found` check already catches them.

## Refreshing the popular-packages list

```bash
node scripts/update-popular.ts
```

This needs network access and takes about 1.5 hours, because npm rate-limits its
download API. If it stops, rerun it and it resumes from its checkpoint. On a later
(UTC) day, pass the date range it printed, for example
`--range 2026-11-01:2026-11-07`, so every count covers the same week. The data sources
are described in [ADR 0003](docs/adr/0003-popular-packages-data-source.md). Review the
diff before you commit it.
