// The runtime layer end to end: child processes run the synthetic fixture app under
// `node --import <src/runtime/register.ts>`. The fixture packages are inert; the only
// network use is fetch of data: URLs and a server on 127.0.0.1.

import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { parseObserved, type ObservedFile } from "../src/index.ts";

const REGISTER = pathToFileURL(fileURLToPath(new URL("../src/runtime/register.ts", import.meta.url))).href;
const APP = fileURLToPath(new URL("./fixtures/app/", import.meta.url));

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "depward-caps-runtime-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function runApp(script: string, args: string[] = [], env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ["--import", REGISTER, join(APP, script), ...args],
      { cwd: dir, env: { ...process.env, DEPWARD_CAPS_OUT: "", DEPWARD_CAPS_MODE: "", DEPWARD_CAPS_ENV: "", ...env }, timeout: 30_000 },
      (err, stdout, stderr) => resolve({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout, stderr }),
    );
  });
}

async function observed(path = join(dir, ".depward", "caps-observed.json")): Promise<ObservedFile> {
  const file = parseObserved(await readFile(path, "utf8"));
  if (file === null) throw new Error("malformed observed file");
  return file;
}

const summary = (o: ObservedFile): Record<string, Record<string, number>> =>
  Object.fromEntries(Object.entries(o.packages).map(([k, caps]) => [k, Object.fromEntries(Object.entries(caps).map(([c, u]) => [c, u.count]))]));

describe("observe mode", () => {
  test("Express + Prisma-like app: every use is attributed to the right package", async () => {
    const r = await runApp("server.mjs", ["30"], { PRISMA_API_KEY: "k" });
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    const o = await observed();
    // 30 requests, 10 per route: /users (ORM: 2 fs + 1 crypto, JSON etag), / (file
    // stream), /health (JSON etag). Plus the schema read and the server at startup.
    expect(summary(o)).toEqual({
      "etag-lite@1.0.0": { crypto: 20 },
      "orm-client@1.0.0": { crypto: 10, env: 1, fs: 21 },
      "web-framework@1.0.0": { fs: 10, net: 1 },
    });
    expect(o.packages["orm-client@1.0.0"]?.["env"]?.members).toEqual(["process.env.PRISMA_API_KEY"]);
    expect(o.packages["web-framework@1.0.0"]?.["net"]?.members).toEqual(["http.Server"]);
  }, 60_000);

  test("CJS, ESM, classes, streams, patches, live bindings, globals all keep working", async () => {
    const r = await runApp("checks.mjs");
    expect(r.code).toBe(0);
    const checks = JSON.parse(r.stdout) as Record<string, unknown>;
    const { bypass, ...rest } = checks;
    expect(Object.entries(rest).filter(([, v]) => v !== true)).toEqual([]);
    // Documented bypasses (true = got the real fs); createRequire, import() and
    // getBuiltinModule are covered.
    expect(bypass).toMatchObject({ createRequire: false, dynamicImport: false, getBuiltinModule: false, moduleLoad: true, processBinding: "raw binding reachable" });

    const o = summary(await observed());
    expect(o["etag-lite@1.0.0"]).toEqual({ crypto: 1 }); // nested node_modules: not its parent
    expect(o["web-framework@1.0.0"]?.["crypto"]).toBeUndefined();
    expect(o["bundled-pkg@1.0.0"]).toEqual({ fs: 1 }); // inlined helper → the bundle
    // util.promisify(fs.exists) uses fs.exists[util.promisify.custom], which Node defines
    // non-configurable and non-writable: a Proxy must return it unwrapped (documented gap).
    expect(o["@scope/pure-util@1.0.0"]).toBeUndefined();
    expect(o["fetch-client@1.0.0"]).toEqual({ env: 1, net: 2 }); // incl. fetch from a timer
    expect(Object.keys(o)).not.toContain("sneaky@1.0.0"); // Node's own env reads aren't blamed
  }, 60_000);

  test("runs accumulate in the observed file; DEPWARD_CAPS_OUT moves it", async () => {
    const out = join(dir, "obs.json");
    await runApp("server.mjs", ["3"], { DEPWARD_CAPS_OUT: out });
    await runApp("server.mjs", ["3"], { DEPWARD_CAPS_OUT: out });
    // Per run: one /users query (2 fs + 1 crypto), the schema read, and one read of the
    // credential-like PRISMA_API_KEY (attributed whether or not it is set).
    expect(summary(await observed(out))["orm-client@1.0.0"]).toEqual({ crypto: 2, env: 2, fs: 6 });
  }, 60_000);

  test("DEPWARD_CAPS_ENV=all attributes ordinary env reads too", async () => {
    await runApp("server.mjs", ["3"], { DEPWARD_CAPS_ENV: "all" });
    const o = await observed();
    expect(o.packages["web-framework@1.0.0"]?.["env"]?.members).toEqual(["process.env.NODE_ENV"]);
    expect(o.packages["orm-client@1.0.0"]?.["env"]?.members).toEqual(expect.arrayContaining(["process.env.DATABASE_URL", "process.env.PRISMA_API_KEY"]));
  }, 60_000);

  test("an unknown mode warns and observes", async () => {
    const r = await runApp("server.mjs", ["3"], { DEPWARD_CAPS_MODE: "strict" });
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("unknown DEPWARD_CAPS_MODE=strict");
    expect(Object.keys((await observed()).packages)).toContain("orm-client@1.0.0");
  }, 60_000);
});

/** Writes `dir/capabilities.lock.json` approving `packages`. */
function lockfile(packages: Record<string, string[]>): Promise<void> {
  return writeFile(join(dir, "capabilities.lock.json"), JSON.stringify({ version: 1, packages: Object.fromEntries(Object.entries(packages).map(([k, caps]) => [k, { capabilities: caps }])) }));
}

describe("enforce mode", () => {
  const SERVER_CAPS = { "orm-client@1.0.0": ["crypto", "env", "fs"], "web-framework@1.0.0": ["fs", "net"], "etag-lite@1.0.0": ["crypto"] };

  // A package that replaces a built-in the runtime uses must not turn a denial into an
  // approval (ADR 0007: intrinsics are captured at startup). fs is approved only for
  // identities a tampered runtime could be tricked into using.
  const tamperer = createRequire(import.meta.url)(join(APP, "node_modules", "tamperer")) as { PROBES: string[]; ACCESS: string[] };
  test.each(tamperer.PROBES)("tampering with %s doesn't turn a denial into an approval", async (probe) => {
    await lockfile({ "tamperer@1.0.0": [], "tamperer@0.0.1": ["env", "fs"], "other@1.0.0": ["env", "fs"] });
    const r = await runApp("tamper.mjs", [probe], { DEPWARD_CAPS_MODE: "enforce" });
    const out = JSON.parse(r.stdout || "{}") as Record<string, { code?: string }>;
    expect(Object.fromEntries(tamperer.ACCESS.map((how) => [how, out[how]?.code])), r.stderr).toEqual(Object.fromEntries(tamperer.ACCESS.map((how) => [how, "CAPS_DENIED"])));
  }, 60_000);

  test("approved uses run; an unapproved use throws DepwardCapabilityError naming package, capability and call site", async () => {
    await lockfile(SERVER_CAPS);
    const r = await runApp("enforce.mjs", [], { DEPWARD_CAPS_MODE: "enforce" });
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout) as Record<string, { ok?: unknown; error?: string; code?: string; denied?: { package: string; capability: string; member: string; callSite: string | null } }>;
    expect(out["approved"]).toEqual({ ok: 2 });
    expect(out["importOnly"]).toEqual({ ok: "function" }); // importing is never denied
    expect(out["denied"]).toMatchObject({ error: "DepwardCapabilityError", code: "CAPS_DENIED", denied: { package: "esm-logger@1.0.0", capability: "os_info", member: "os.hostname" } });
    expect(out["denied"]?.denied?.callSite).toMatch(/node_modules[/\\]esm-logger[/\\]index\.js:\d+:\d+$/);
    expect(out["afterDenial"]).toEqual({ ok: "function" });
    expect(out["fetchDenied"]?.denied).toMatchObject({ package: "fetch-client@1.0.0", capability: "net", member: "globalThis.fetch" });
    expect(out["envDenied"]?.denied).toMatchObject({ package: "fetch-client@1.0.0", capability: "env", member: "process.env.SPIKE_TOKEN" });
    expect(out["app"]).toEqual({ ok: true }); // application code is never restricted
  }, 60_000);

  test("the Express + Prisma-like app runs when its capabilities are approved, and fails when one isn't", async () => {
    await lockfile(SERVER_CAPS);
    expect((await runApp("server.mjs", ["9"], { DEPWARD_CAPS_MODE: "enforce" })).code).toBe(0);
    await lockfile({ ...SERVER_CAPS, "orm-client@1.0.0": ["crypto", "env"] });
    const denied = await runApp("server.mjs", ["9"], { DEPWARD_CAPS_MODE: "enforce" });
    expect(denied.code).not.toBe(0);
    expect(denied.stderr).toContain("orm-client@1.0.0 used capability");
  }, 60_000);

  test("without an exact entry, the highest approved version of the name is the reference", async () => {
    await lockfile({ "orm-client@0.9.0": ["crypto", "env", "fs"], "web-framework@1.0.0": ["fs", "net"], "etag-lite@1.0.0": ["crypto"] });
    expect((await runApp("server.mjs", ["3"], { DEPWARD_CAPS_MODE: "enforce" })).code).toBe(0);
  }, 60_000);

  test("fails closed at startup when the capability lockfile is missing or invalid", async () => {
    const missing = await runApp("server.mjs", ["1"], { DEPWARD_CAPS_MODE: "enforce" });
    expect(missing.code).not.toBe(0);
    expect(missing.stderr).toContain("enforce mode needs a capability lockfile");
    await writeFile(join(dir, "caps.json"), '{"version":2}');
    const invalid = await runApp("server.mjs", ["1"], { DEPWARD_CAPS_MODE: "enforce", DEPWARD_CAPS_LOCKFILE: "caps.json" });
    expect(invalid.code).not.toBe(0);
    expect(invalid.stderr).toContain("not a version 1 capability lockfile");
  }, 60_000);
});
