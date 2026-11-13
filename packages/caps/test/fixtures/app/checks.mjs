// Behavior probes for the runtime layer, run as application code under
// `node --import <register>`. Prints one JSON object; test/runtime.test.ts checks it.
import { createRequire, syncBuiltinESMExports } from "node:module";
import realFs, { readFileSync as rootReadFileSync } from "node:fs";
import http from "node:http";
import stream from "node:stream";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";

const require = createRequire(import.meta.url);
const dir = fileURLToPath(new URL("./data/", import.meta.url));
const results = {};
const check = async (name, fn) => {
  try {
    results[name] = await fn();
  } catch (e) {
    results[name] = `threw ${e.name}: ${e.message}`;
  }
};
const wrapped = (x) => x !== realFs && typeof x?.readFileSync === "function";

// CJS and ESM get working, per-package wrappers.
const orm = require("orm-client");
await check("cjs.wrapped", () => wrapped(orm.fs));
await check("cjs.readFileSync", () => new orm.OrmClient(dir).schema.startsWith("model User"));
await check("cjs.fsPromises", async () => (await new orm.OrmClient(dir).findMany("users")).rows.length === 2);
await check("cjs.fsPromisesIdentity", () => orm.fs.promises === orm.fsp);
const logger = await import("esm-logger");
const logFile = join(tmpdir(), `depward-caps-runtime-${process.pid}.log`);
await check("esm.namedAndDefault", () => logger.log(logFile, "hello") > 0 && logger.readBack(logFile).includes("hello"));
await check("esm.wrapped", () => wrapped(logger.fs));
await check("esm.namespace", () => typeof logger.os.hostname() === "string");
const framework = require("web-framework");
await check("perPackageObjects", () => framework.fs !== orm.fs && wrapped(framework.fs));

// instanceof, streams, subclassing, promisify, patches, live bindings, unwrapping.
await check("streamInstanceof", () => {
  const s = orm.fs.createReadStream(join(dir, "db.json"));
  const ok = s instanceof orm.fs.ReadStream && s instanceof realFs.ReadStream && s instanceof stream.Readable;
  s.destroy();
  return ok;
});
await check("subclassHttpServer", async () => {
  const app = framework().get("/", (_req, res) => res.json({ ok: true }));
  const server = await new Promise((resolve) => app.listen(0, resolve));
  const ok = server instanceof http.Server;
  const { port } = server.address();
  const body = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  server.close();
  return ok && body === '{"ok":true}';
});
const pure = require("@scope/pure-util");
await check("promisifyCustom", async () => (await pure.promisifiedExists(join(dir, "db.json"))) === true);
await check("fnNameAndLength", () => pure.readFileName === "readFile" && pure.readFileLength === realFs.readFile.length);
const patcher = require("fs-patcher");
await check("patchReachesRealModule", () => {
  const patched = patcher.patch();
  orm.fs.readFileSync(join(dir, "db.json"));
  return realFs.readFileSync === patched && patched.calls === 1;
});
await check("liveBinding.esmNamedAfterSync", () => {
  syncBuiltinESMExports();
  const before = realFs.readFileSync.calls;
  logger.readBack(join(dir, "db.json"));
  return rootReadFileSync === realFs.readFileSync && realFs.readFileSync.calls === before + 1;
});
patcher.unpatch();
syncBuiltinESMExports();
await check("wrapperNotLeaked", () => {
  patcher.leak();
  return realFs.leakedStat === realFs.statSync;
});
await check("bundled", () => require("bundled-pkg").hasFile(join(dir, "db.json")));

// Globals.
process.env.SPIKE_TOKEN = "t0k3n";
const fc = await import("fetch-client");
await check("fetch", async () => (await fc.get()) === "hello");
await check("fetchFromTimer", async () => (await fc.later()) === "later");
await check("env", () => fc.token() === "t0k3n");
await check("envEnumerable", () => Object.keys(process.env).includes("SPIKE_TOKEN"));

// Known bypasses (true = got the real fs). Documented, not fixed.
const probes = require("sneaky")(realFs);
probes.dynamicImport = await probes.dynamicImport;
results.bypass = probes;

realFs.rmSync(logFile, { force: true });
process.stdout.write(JSON.stringify(results, null, 2) + "\n");
