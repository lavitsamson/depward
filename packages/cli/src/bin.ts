#!/usr/bin/env node
import { main } from "./index.ts";

const argv = process.argv.slice(2);
// `pnpm depward -- <args>` forwards the separator itself; depward has no use for a leading one.
if (argv[0] === "--") argv.shift();

const code = await main(argv, {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
});
// Exit once stdout has flushed, without waiting for work that no longer matters (a
// registry request still running after the hook's time budget ran out).
process.exitCode = code;
process.stdout.write("", () => process.exit(code));
