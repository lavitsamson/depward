#!/usr/bin/env node
import { main } from "./index.ts";

const argv = process.argv.slice(2);
// `pnpm depward -- <args>` forwards the separator itself; depward has no use for a leading one.
if (argv[0] === "--") argv.shift();

process.exitCode = await main(argv, {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
});
