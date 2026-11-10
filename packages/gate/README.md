# @depward/gate

Answers one question before anything is installed: should this package or install command be allowed? The result is `allow`, `ask`, or `deny`, with reasons.

> **Status:** pre-release (Phase 2). The install-command tokenizer (M2.1), registry
> checks (M2.2), and tarball checks (M2.3) are done. The policy engine comes next. See
> the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { checkRegistry, parseInstallCommand } from "@depward/gate";
import { createRegistryClient } from "@depward/core";

const { requests, findings } = parseInstallCommand('cd app && npx -y create-vite@latest x && npm i -D "zod@^3"');
for (const r of requests) console.log(r.via, r.manager, `${r.name}@${r.range}`);
// exec npm create-vite@latest
// install npm zod@^3
console.log(findings); // []

const registry = createRegistryClient();
const result = await checkRegistry({ name: "react-codeshift", range: "latest" }, { registry });
for (const f of result.findings) console.log(f.severity, f.id, f.message);
// critical known-hallucinated-name react-codeshift is a package name AI models are documented to hallucinate. Did you mean jscodeshift?
// medium low-downloads react-codeshift has 11 downloads in the last week (minimum 500).
console.log(result.suggestion); // { name: 'jscodeshift' }
```

`parseInstallCommand` never runs anything. It understands npm, pnpm, yarn, and bun
install and exec forms (`npx`, `dlx`, `bunx`, `create`/`init`), chained commands,
subshells, `$(…)` substitutions, `sh -c` / `eval` / `cmd /c` / `powershell -Command`
strings, heredocs piped into a shell, and prefixes such as `VAR=x`, `env`, and `sudo`.
Known limits: it doesn't follow shell scripts on disk, package.json scripts, or text piped
into a shell from another program (`echo "npm i x" | sh`).

`checkRegistry` reads registry metadata only (the packument and the weekly download
count). It checks for missing, hallucinated, and typosquatted names, versions that are
too new, new or unpopular packages, publisher and maintainer changes, dropped
provenance, and deprecation. Every finding ID is described in
[docs/findings.md](../../docs/findings.md). Network failures are returned in
`result.errors`; they are never thrown.

`checkPackage` runs the registry checks and then the tarball checks: it downloads the
resolved version's tarball, verifies its integrity hash, reads it in memory, and runs
[`@depward/analyzer`](../analyzer) on it. Package code is never executed and extracted
files are never written to disk. A tampered or unsafe archive (`..` paths, corrupt,
over the size limits) is reported as a finding, not an error.

## Data and licensing

The code is MIT licensed. The package also ships two data files in `dist/data/`:

- `popular-packages.json`: about 10,000 popular npm package names with weekly download
  counts, used by the typosquat check. The selection of names is derived from
  [ecosyste.ms](https://ecosyste.ms) package data, licensed under
  [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The download counts
  come from the npm download-counts API (<https://api.npmjs.org>). **This file is
  licensed under CC BY-SA 4.0.** Keep this attribution if you redistribute or adapt it.
- `hallucinated-names.json`: package names that AI models are publicly documented to
  invent, each with its source. MIT, like the code.

Requires Node.js >= 22.15. ESM only.
