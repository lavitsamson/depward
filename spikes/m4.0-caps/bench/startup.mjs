// Loads every fixture package once, then exits. Measures hook + wrapper startup cost.
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const require = createRequire(new URL("../app/", import.meta.url));
for (const name of ["web-framework", "orm-client", "bundled-pkg", "fs-patcher", "@scope/pure-util", "bench-calls"]) require(name);
for (const name of ["esm-logger", "fetch-client"]) await import(pathToFileURL(require.resolve(name)).href);
