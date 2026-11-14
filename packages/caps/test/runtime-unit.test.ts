// Unit tests of the runtime layer's pure parts. Nothing here installs hooks: register.ts
// is only ever loaded in child processes (runtime.test.ts).

import { EventEmitter } from "node:events";
import { describe, expect, test } from "vitest";
import { createAttribution, packageOf, stackLineLocation } from "../src/runtime/attribution.ts";
import { isSensitiveEnvKey } from "../src/runtime/globals.ts";
import { capabilityBuiltin, capsUrl, createHooks, generatedSource, parseCapsUrl } from "../src/runtime/hooks.ts";
import { createStore, mergeObserved, parseObserved, writeObserved, type ObservedFile } from "../src/runtime/store.ts";
import { createWrapper } from "../src/runtime/wrap.ts";
import { DepwardCapabilityError } from "../src/runtime/errors.ts";
import { parsePolicy } from "../src/runtime/policy.ts";

const next = (s: string) => ({ url: `next:${s}` });
const exists = () => true;
const custom = () => Promise.resolve(true);

describe("packageOf", () => {
  test.each([
    ["file:///app/node_modules/express/lib/router.js", "express", "file:///app/node_modules/express"],
    ["C:\\app\\node_modules\\@scope\\pkg\\index.js", "@scope/pkg", "C:/app/node_modules/@scope/pkg"],
    ["/app/node_modules/a/node_modules/b/x.js", "b", "/app/node_modules/a/node_modules/b"],
    ["/app/node_modules/.pnpm/b@1.0.0/node_modules/b/x.js", "b", "/app/node_modules/.pnpm/b@1.0.0/node_modules/b"],
    ["file:///app/node_modules/%40scope/pkg/x.js", "@scope/pkg", "file:///app/node_modules/%40scope/pkg"],
  ])("%s", (location, name, root) => {
    expect(packageOf(location)).toEqual({ name, root });
  });

  test.each(["/app/src/index.js", "file:///app/node_modules/.bin/x", "/app/node_modules/"])("%s is application code", (location) => {
    expect(packageOf(location)).toBeNull();
  });
});

test("stackLineLocation", () => {
  expect(stackLineLocation("    at get (file:///app/node_modules/a/index.js:3:9)")).toBe("file:///app/node_modules/a/index.js");
  expect(stackLineLocation("    at C:\\app\\node_modules\\a\\index.js:3:9")).toBe("C:\\app\\node_modules\\a\\index.js");
  expect(stackLineLocation("    at Array.map (<anonymous>)")).toBeNull();
});

describe("createAttribution", () => {
  const files: Record<string, string> = { "/app/node_modules/a/package.json": '{"version":"1.2.3"}' };
  const reads: string[] = [];
  const attr = createAttribution({
    selfRoots: ["/app/node_modules/@depward/caps/dist/"],
    readFile: (p) => {
      reads.push(p);
      const text = files[p.replaceAll("\\", "/")];
      if (text === undefined) throw new Error("ENOENT");
      return text;
    },
  });

  test("keys by name@version from package.json, cached per directory", () => {
    expect(attr.keyOf("/app/node_modules/a/index.js")).toBe("a@1.2.3");
    expect(attr.keyOf("/app/node_modules/a/lib/x.js")).toBe("a@1.2.3");
    expect(reads).toHaveLength(1);
    expect(attr.keyOf("/app/node_modules/b/index.js")).toBe("b@unknown");
    expect(attr.keyOf("/app/index.js")).toBeNull();
  });

  test("its own directory is self", () => {
    expect(attr.isSelf("/app/node_modules/@depward/caps/dist/register.mjs")).toBe(true);
    expect(attr.isSelf("/app/node_modules/@depward/caps-other/x.js")).toBe(false);
  });

  test("caller() from this test file is application code", () => {
    expect(attr.caller()).toBeNull();
  });
});

describe("hooks", () => {
  test("capability builtins, with or without node:", () => {
    expect(capabilityBuiltin("fs")).toBe("fs");
    expect(capabilityBuiltin("node:fs/promises")).toBe("fs/promises");
    expect(capabilityBuiltin("path")).toBeNull();
    expect(capabilityBuiltin("node:constructor")).toBeNull();
  });

  test("capsUrl round-trips, including scoped keys", () => {
    const url = capsUrl("child_process", "@scope/pkg@1.0.0", "esm");
    expect(parseCapsUrl(url)).toEqual({ name: "child_process", key: "@scope/pkg@1.0.0", kind: "esm" });
    expect(parseCapsUrl("depward-cap:path?pkg=a%401&kind=cjs")).toBeNull();
    expect(parseCapsUrl("file:///x.js")).toBeNull();
  });

  test("generated sources", () => {
    expect(generatedSource("fs", "a@1.0.0", "cjs", ["readFileSync"])).toEqual({
      format: "commonjs",
      source: 'module.exports = globalThis[Symbol.for("depward.caps")].moduleFor("fs", "a@1.0.0");\n',
    });
    const esm = generatedSource("fs", "a@1.0.0", "esm", ["readFileSync", "default", "odd-name"]);
    expect(esm.format).toBe("module");
    expect(esm.source).toContain('let e0 = m.readFileSync;\nexport { e0 as "readFileSync" };');
    expect(esm.source).toContain('let e1 = m["odd-name"];');
    expect(esm.source).toContain("r.onSync(() => { e0 = m.readFileSync; e1 = m[\"odd-name\"]; });");
    expect(esm.source).not.toContain('as "default"');
  });

  test("resolve redirects only capability builtins imported from packages", () => {
    const hooks = createHooks({ importer: (u) => (u.includes("/node_modules/a/") ? "a@1.0.0" : null), exportNames: () => [] });
    const req = { parentURL: "file:///app/node_modules/a/i.js", conditions: ["require", "node"] };
    expect(hooks.resolve("node:fs", req, next)).toEqual({ url: "depward-cap:fs?pkg=a%401.0.0&kind=cjs", shortCircuit: true });
    expect(hooks.resolve("fs", { ...req, conditions: ["import", "node"] }, next)).toEqual({ url: "depward-cap:fs?pkg=a%401.0.0&kind=esm", shortCircuit: true });
    expect(hooks.resolve("path", req, next)).toEqual({ url: "next:path" });
    expect(hooks.resolve("fs", { parentURL: "file:///app/index.js", conditions: ["import"] }, next)).toEqual({ url: "next:fs" });
  });
});

describe("createWrapper", () => {
  class Thing extends EventEmitter {}
  const real = {
    double: (x: number) => x * 2,
    Thing,
    promises: { read: async () => "ok" },
    constant: 42,
  };

  test("counts calls per package and member, keeps classes and instanceof working", async () => {
    const store = createStore();
    const w = createWrapper({ store, use: (r) => void r.count++ });
    const a = w.wrapModule(real, "mod", "fs", "a@1.0.0") as typeof real;
    const b = w.wrapModule(real, "mod", "fs", "b@1.0.0") as typeof real;
    expect(a).not.toBe(b);
    expect(w.wrapModule(real, "mod", "fs", "a@1.0.0")).toBe(a);
    expect(a.double(2)).toBe(4);
    expect(a.double(3)).toBe(6);
    expect(b.double(1)).toBe(2);
    const t = new a.Thing();
    expect(t).toBeInstanceOf(Thing);
    expect(t).toBeInstanceOf(a.Thing);
    expect(await a.promises.read()).toBe("ok");
    expect(a.constant).toBe(42);
    expect(store.snapshot().packages).toEqual({
      "a@1.0.0": { fs: { count: 4, members: ["mod.Thing", "mod.double", "mod.promises.read"] } },
      "b@1.0.0": { fs: { count: 1, members: ["mod.double"] } },
    });
  });

  test("own function properties of functions are wrapped, unless frozen; inherited ones aren't", () => {
    const realpath = Object.assign(() => "a", { native: () => "n" });
    Object.defineProperty(exists, Symbol.for("custom"), { value: custom });
    const store = createStore();
    const w = createWrapper({ store, use: (r) => void r.count++ });
    const m = w.wrapModule({ realpath, exists }, "fs", "fs", "a@1.0.0") as { realpath: typeof realpath; exists: typeof exists & Record<symbol, unknown> };
    expect(m.realpath.native()).toBe("n");
    expect(m.exists[Symbol.for("custom")]).toBe(custom); // proxy invariant: must be the real value
    expect(m.realpath.call(null)).toBe("a");
    expect(store.snapshot().packages["a@1.0.0"]?.["fs"]).toEqual({ count: 2, members: ["fs.realpath", "fs.realpath.native"] });
  });

  test("writes through a wrapper store the real function", () => {
    const target: Record<string, unknown> = { f: () => 1 };
    const w = createWrapper({ store: createStore(), use: () => {} });
    const m = w.wrapModule(target, "mod", "fs", "a@1.0.0") as Record<string, unknown>;
    m["alias"] = m["f"];
    expect(target["alias"]).toBe(target["f"]);
    expect(w.unwrap(m["f"])).toBe(target["f"]);
  });
});

test("isSensitiveEnvKey", () => {
  expect(["NPM_TOKEN", "aws_secret", "API_KEY", "GITHUB_REF", "DB_PASSWORD"].map(isSensitiveEnvKey)).toEqual([true, true, true, true, true]);
  expect(["NODE_ENV", "PATH", "npm_config_cache", "HIGH_WATER", "DATABASE_URL"].map(isSensitiveEnvKey)).toEqual([false, false, false, false, false]);
});

describe("observed file", () => {
  const a: ObservedFile = { version: 1, packages: { "x@1.0.0": { fs: { count: 2, members: ["fs.readFileSync"] } } } };
  const b: ObservedFile = { version: 1, packages: { "x@1.0.0": { fs: { count: 1, members: ["fs.statSync", "fs.readFileSync"] }, net: { count: 1, members: ["globalThis.fetch"] } } } };

  test("merge adds counts and unions sorted members", () => {
    expect(mergeObserved(a, b)).toEqual({
      version: 1,
      packages: { "x@1.0.0": { fs: { count: 3, members: ["fs.readFileSync", "fs.statSync"] }, net: { count: 1, members: ["globalThis.fetch"] } } },
    });
  });

  test("parse rejects malformed files", () => {
    expect(parseObserved(JSON.stringify(a))).toEqual(a);
    for (const bad of ["{", "[]", '{"version":2,"packages":{}}', '{"version":1,"packages":{"x":{"fs":{"count":-1,"members":[]}}}}', '{"version":1,"packages":{"x":{"fs":{"count":1,"members":[1]}}}}']) {
      expect(parseObserved(bad), bad).toBeNull();
    }
  });

  test("write merges with the existing file and skips empty observations", () => {
    const disk = new Map<string, string>([["/o.json", JSON.stringify(a)]]);
    const io = {
      readFile: (p: string) => {
        const t = disk.get(p);
        if (t === undefined) throw new Error("ENOENT");
        return t;
      },
      writeFile: (p: string, t: string) => void disk.set(p, t),
      rename: (from: string, to: string) => {
        disk.set(to, disk.get(from) ?? "");
        disk.delete(from);
      },
      mkdir: () => {},
    };
    writeObserved("/o.json", "/", b, io);
    expect(parseObserved(disk.get("/o.json") ?? "")?.packages["x@1.0.0"]?.["fs"]?.count).toBe(3);
    writeObserved("/empty.json", "/", { version: 1, packages: {} }, io);
    expect(disk.has("/empty.json")).toBe(false);
  });
});

describe("enforce policy", () => {
  const policy = parsePolicy(
    JSON.stringify({
      version: 1,
      packages: { "a@1.0.0": { capabilities: ["fs"] }, "a@1.10.0": { capabilities: ["net"] }, "a@1.9.0": { capabilities: ["env"] }, "b@1.0.0": { capabilities: [] } },
    }),
    "caps.json",
  );

  test("exact entry, else the highest version of the name; unknown packages get nothing", () => {
    expect(policy.allows("a@1.0.0", "fs")).toBe(true);
    expect(policy.allows("a@1.0.0", "net")).toBe(false);
    expect(policy.allows("a@2.0.0", "net")).toBe(true);
    expect(policy.allows("a@unknown", "net")).toBe(true);
    expect(policy.allows("b@1.0.0", "fs")).toBe(false);
    expect(policy.allows("c@1.0.0", "fs")).toBe(false);
  });

  test.each(["{", '{"version":2,"packages":{}}', '{"version":1,"packages":{"a":{"capabilities":[]}}}', '{"version":1,"packages":{"a@1.0.0":{"capabilities":[1]}}}'])("rejects %s", (text) => {
    expect(() => parsePolicy(text, "caps.json")).toThrow(expect.objectContaining({ name: "DepwardCapabilityError", code: "CAPS_POLICY" }));
  });
});

describe("DepwardCapabilityError", () => {
  test("names the package, capability, member and call site, with an approval hint", () => {
    const e = DepwardCapabilityError.denied({ package: "@s/x@1.2.3", capability: "net", member: "globalThis.fetch", callSite: "file:///app/node_modules/@s/x/i.js:4:2" });
    expect(e.code).toBe("CAPS_DENIED");
    expect(e.message).toBe(
      'package @s/x@1.2.3 used capability "net" (globalThis.fetch) at file:///app/node_modules/@s/x/i.js:4:2, which capabilities.lock.json does not approve. If it is expected: depward caps approve @s/x --cap net --reason "..."',
    );
    expect(e).toBeInstanceOf(Error);
  });

  test("strips control characters from untrusted names", () => {
    const e = DepwardCapabilityError.denied({ package: "\u001b[31mevil@1.0.0", capability: "fs", member: "fs.readFileSync", callSite: null });
    expect([...e.message].some((ch) => (ch.codePointAt(0) ?? 0) < 0x20)).toBe(false);
  });
});
