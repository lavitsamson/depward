// Behavior checks for spec questions 1–4. Run as application code (not in node_modules),
// so its own builtin imports are the real modules:
//   node --import ../register.mjs checks.mjs            (from spikes/m4.0-caps/app)
// Prints one JSON object; run-checks.mjs compares it with the expected answers.
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

// Q1: CJS require and ESM import both get a working, per-package module object.
const orm = require("orm-client");
await check("q1.cjs.wrapped", () => wrapped(orm.fs));
await check("q1.cjs.readFileSync", () => new orm.OrmClient(dir).schema.startsWith("model User"));
await check("q1.cjs.fsPromises", async () => (await new orm.OrmClient(dir).findMany("users")).rows.length === 2);
await check("q1.cjs.fsPromisesIdentity", () => orm.fs.promises === orm.fsp);
const logger = await import("esm-logger");
const logFile = join(tmpdir(), `depward-spike-${process.pid}.log`);
await check("q1.esm.namedAndDefault", () => logger.log(logFile, "hello") > 0 && logger.readBack(logFile).includes("hello"));
await check("q1.esm.wrapped", () => wrapped(logger.fs));
await check("q1.esm.namespaceOs", () => typeof logger.os.hostname() === "string");
const framework = require("web-framework");
await check("q1.perPackageObjects", () => framework.fs !== orm.fs && wrapped(framework.fs));
await check("q1.nestedDependencyWorks", () => {
  const etag = require(join(dir, "..", "node_modules", "web-framework", "node_modules", "etag-lite"));
  return etag("x").length > 10;
});

// Q2: instanceof, streams, subclassing, statics, promisify, monkey patching, live bindings.
await check("q2.streamInstanceofWrappedClass", () => {
  const s = orm.fs.createReadStream(join(dir, "db.json"));
  const ok = s instanceof orm.fs.ReadStream && s instanceof realFs.ReadStream && s instanceof stream.Readable;
  s.destroy();
  return ok;
});
await check("q2.subclassWrappedHttpServer", async () => {
  const app = framework().get("/", (_req, res) => res.json({ ok: true }));
  const server = await new Promise((resolve) => app.listen(0, resolve));
  const ok = server instanceof http.Server && server instanceof framework.ServerClass;
  const { port } = server.address();
  const body = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  server.close();
  return ok && body === '{"ok":true}';
});
await check("q2.classIdentity", () => framework.ServerClass === http.Server);
const pure = require("@scope/pure-util");
await check("q2.promisifyCustom", async () => (await pure.promisifiedExists(join(dir, "db.json"))) === true);
await check("q2.promisify", async () => (await pure.readFile(join(dir, "db.json"), "utf8")).includes("ada"));
await check("q2.fnNameAndLength", () => pure.readFileName === "readFile" && pure.readFileLength === realFs.readFile.length);
const patcher = require("fs-patcher");
await check("q2.monkeyPatchReachesRealModule", () => {
  const patched = patcher.patch();
  const ok = realFs.readFileSync === patched && typeof orm.fs.readFileSync === "function";
  orm.fs.readFileSync(join(dir, "db.json"));
  const calls = patched.calls;
  return ok && calls === 1;
});
await check("q2.liveBinding.rootEsmAfterSync", () => {
  syncBuiltinESMExports();
  return rootReadFileSync === realFs.readFileSync;
});
await check("q2.liveBinding.wrappedEsmDefaultSeesPatch", () => {
  const before = realFs.readFileSync.calls;
  logger.fs.readFileSync(join(dir, "db.json"));
  return realFs.readFileSync.calls === before + 1;
});
await check("q2.liveBinding.wrappedEsmNamedSeesPatch", () => {
  const before = realFs.readFileSync.calls;
  logger.readBack(join(dir, "db.json"));
  return realFs.readFileSync.calls === before + 1;
});
patcher.unpatch();
syncBuiltinESMExports();

// Q3: bundled code is attributed to the bundle's package (checked in observations).
await check("q3.bundledWorks", () => require("bundled-pkg").hasFile(join(dir, "db.json")));

// Q4: globals via stack attribution.
process.env.SPIKE_TOKEN = "t0k3n";
const fc = await import("fetch-client");
await check("q4.fetch", async () => (await fc.get()) === "hello");
await check("q4.fetchFromTimer", async () => (await fc.later()) === "later");
await check("q4.env", () => fc.token() === "t0k3n");
await check("q4.envEnumerable", () => Object.keys(process.env).includes("SPIKE_TOKEN"));

// Bypass probes (documented in the ADR; these are expected to succeed).
const probes = require("sneaky")(realFs);
probes.dynamicImport = await probes.dynamicImport;
results.bypass = probes;

realFs.rmSync(logFile, { force: true });
process.stdout.write(JSON.stringify(results, null, 2) + "\n");
