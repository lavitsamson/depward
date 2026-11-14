// Enforce-mode probes, run as application code under
//   DEPWARD_CAPS_MODE=enforce node --import <register> enforce.mjs
// with a capability lockfile in the working directory. Prints one JSON object.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { existsSync } from "node:fs";

const require = createRequire(import.meta.url);
const dir = fileURLToPath(new URL("./data/", import.meta.url));
const results = {};
const attempt = async (name, fn) => {
  try {
    results[name] = { ok: await fn() };
  } catch (e) {
    results[name] = { error: e.name, code: e.code, denied: e.denied ?? null, message: e.message };
  }
};

await attempt("approved", async () => (await new (require("orm-client").OrmClient)(dir).findMany("users")).rows.length);
// Importing a package that holds fs is fine; using it is not.
const logger = await import("esm-logger");
await attempt("importOnly", () => typeof logger.log);
await attempt("denied", () => logger.log(join(tmpdir(), "depward-caps-enforce.log"), "x"));
// The application can catch the error and carry on.
await attempt("afterDenial", () => typeof logger.readBack);
const fc = await import("fetch-client");
await attempt("fetchDenied", () => fc.get());
process.env.SPIKE_TOKEN = "t0k3n";
await attempt("envDenied", () => fc.token());
await attempt("app", () => existsSync(dir));
process.stdout.write(JSON.stringify(results, null, 2) + "\n");
