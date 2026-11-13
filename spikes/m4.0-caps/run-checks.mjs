// Reproduces the spike's behavior answers. From the repo root:
//   node spikes/m4.0-caps/run-checks.mjs
// Exits 1 if any answer differs from the one recorded in docs/adr/0007-caps-runtime-hooks.md.
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const REGISTER = new URL("./register.mjs", import.meta.url).href;
const failures = [];
const expect = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures.push(`${name}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
};
const run = (script, env = {}) => {
  const r = spawnSync(process.execPath, ["--import", REGISTER, here(script)], { env: { ...process.env, ...env }, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`${script} exited ${r.status}\n${r.stderr}`);
  return JSON.parse(r.stdout);
};

// Q1–Q4 behavior. Everything works except the two documented limitations.
const obsFile = join(tmpdir(), `depward-spike-obs-${process.pid}.json`);
const checks = run("./app/checks.mjs", { DEPWARD_CAPS_OUT: obsFile });
const LIMITATIONS = { "q2.classIdentity": false, "q2.liveBinding.wrappedEsmNamedSeesPatch": false };
for (const [name, value] of Object.entries(checks)) {
  if (name !== "bypass") expect(name, value, LIMITATIONS[name] ?? true);
}
// Bypass probes: true = got the real fs. createRequire, import() and getBuiltinModule are
// covered; Module._load and process.binding are not (documented).
const b = checks.bypass;
expect("bypass.createRequire", b.createRequire, false);
expect("bypass.dynamicImport", b.dynamicImport, false);
expect("bypass.getBuiltinModule", b.getBuiltinModule, false);
expect("bypass.moduleLoad", b.moduleLoad, true);
expect("bypass.processBinding", b.processBinding, "raw binding reachable");

// Attribution: nested, scoped, bundled, globals; no false positive from Node internals.
const observed = JSON.parse(readFileSync(obsFile, "utf8")).observed;
rmSync(obsFile, { force: true });
const has = (pkg, cap) => observed.some((o) => o.pkg === pkg && o.cap === cap);
expect("attr.etag-lite.crypto (nested)", has("etag-lite", "crypto"), true);
expect("attr.web-framework.crypto (parent of nested)", has("web-framework", "crypto"), false);
expect("attr.@scope/pure-util.fs", has("@scope/pure-util", "fs"), true);
expect("attr.bundled-pkg.fs (inlined helper)", has("bundled-pkg", "fs"), true);
expect("attr.fetch-client.net (fetch)", has("fetch-client", "net"), true);
expect("attr.fetch-client.env", has("fetch-client", "env"), true);
expect("attr.sneaky.env (Node-internal read)", has("sneaky", "env"), false);
expect("attr.web-framework.env (NODE_ENV not sensitive)", has("web-framework", "env"), false);

// CJS entry: process.mainModule.require is a bypass (attributed to the app).
const cjs = spawnSync(process.execPath, ["--import", REGISTER, here("./app/cjs-entry.cjs")], { encoding: "utf8" });
expect("bypass.mainModuleRequire", JSON.parse(cjs.stdout).mainModuleRequire, true);

// Enforce mode: import is allowed, use throws a typed error, app code is unrestricted.
const enforce = run("./app/enforce.mjs", { DEPWARD_CAPS_MODE: "enforce", DEPWARD_CAPS_POLICY: here("./app/enforce-policy.json") });
expect("enforce.allowed", enforce["orm-client allowed"], { ok: 2 });
expect("enforce.importOnly", enforce["esm-logger import"], { ok: "function" });
expect("enforce.denied.code", enforce["esm-logger use"].code, "CAPS_DENIED");
expect("enforce.denied.package", enforce["esm-logger use"].package, "esm-logger");
expect("enforce.fetchDenied", enforce["fetch-client fetch"].capability, "net");
expect("enforce.app", enforce["app fs"], { ok: true });

process.stdout.write(`node ${process.version} ${process.platform}: require.resolve("fs") in a package = ${JSON.stringify(b.requireResolve)}\n`);
if (failures.length > 0) {
  process.stdout.write(`FAIL\n  ${failures.join("\n  ")}\n`);
  process.exit(1);
}
process.stdout.write("all spike answers reproduced\n");
