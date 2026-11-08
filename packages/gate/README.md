# @depward/gate

Answers one question before anything is installed: should this package or install command be allowed? The result is `allow`, `ask`, or `deny`, with reasons.

> **Status:** pre-release (Phase 2). The install-command tokenizer (M2.1) is done;
> registry checks and the policy engine come next. See the
> [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { parseInstallCommand } from "@depward/gate";

const { requests, findings } = parseInstallCommand('cd app && npx -y create-vite@latest x && npm i -D "zod@^3"');
for (const r of requests) console.log(r.via, r.manager, `${r.name}@${r.range}`);
// exec npm create-vite@latest
// install npm zod@^3
console.log(findings); // []
```

`parseInstallCommand` never runs anything. It understands npm, pnpm, yarn, and bun
install and exec forms (`npx`, `dlx`, `bunx`, `create`/`init`), chained commands,
subshells, `$(…)` substitutions, `sh -c` / `eval` / `cmd /c` / `powershell -Command`
strings, heredocs piped into a shell, and prefixes such as `VAR=x`, `env`, and `sudo`.
Known limits: it doesn't follow shell scripts on disk, package.json scripts, or text piped
into a shell from another program (`echo "npm i x" | sh`).

Requires Node.js >= 22.15. ESM only. MIT licensed.
