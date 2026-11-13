// Enforce-mode check. Run with:
//   DEPWARD_CAPS_MODE=enforce DEPWARD_CAPS_POLICY=app/enforce-policy.json \
//     node --import ../register.mjs enforce.mjs
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";

const require = createRequire(import.meta.url);
const dir = join(dirname(fileURLToPath(import.meta.url)), "data");
const results = {};
const attempt = async (name, fn) => {
  try {
    results[name] = { ok: await fn() };
  } catch (e) {
    results[name] = { error: e.name, code: e.code, package: e.package, capability: e.capability };
  }
};

// Approved: orm-client has fs, crypto, env.
await attempt("orm-client allowed", async () => (await new (require("orm-client").OrmClient)(dir).findMany("users")).rows.length);
// Importing a package that holds fs is fine; using it is not (esm-logger has no approval).
const logger = await attempt("esm-logger import", async () => typeof (await import("esm-logger")).log);
await attempt("esm-logger use", async () => (await import("esm-logger")).log(join(tmpdir(), "depward-spike-enforce.log"), "x"));
// Globals: fetch-client has no net approval.
await attempt("fetch-client fetch", async () => (await import("fetch-client")).get());
// Application code is never restricted.
await attempt("app fs", async () => (await import("node:fs")).existsSync(dir));
void logger;
process.stdout.write(JSON.stringify(results, null, 2) + "\n");
