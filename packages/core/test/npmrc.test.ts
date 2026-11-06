import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { afterEach, describe, expect, test } from "vitest";
import {
  NPM_REGISTRY,
  Secret,
  authHeaderFor,
  loadNpmConfig,
  nerfDart,
  npmConfigFrom,
  parseNpmrc,
  redactUrl,
  registryFor,
} from "../src/index.ts";

describe("parseNpmrc", () => {
  test("reads key=value pairs, skipping comments and blanks", () => {
    const m = parseNpmrc("; comment\n# also\n\nregistry = https://r.example.com\r\nfoo=\"quoted value\"\nbad line\n");
    expect([...m]).toEqual([
      ["registry", "https://r.example.com"],
      ["foo", "quoted value"],
    ]);
  });

  test("expands ${VAR}, keeps unset ${VAR}, empties unset ${VAR?}, honours escapes", () => {
    const m = parseNpmrc("a=${TOKEN}\nb=${MISSING}\nc=x${MISSING?}y\nd=\\${TOKEN}\n${HOST}=1", { TOKEN: "t0k", HOST: "k" });
    expect(m.get("a")).toBe("t0k");
    expect(m.get("b")).toBe("${MISSING}");
    expect(m.get("c")).toBe("xy");
    expect(m.get("d")).toBe("${TOKEN}");
    expect(m.get("k")).toBe("1");
  });
});

describe("npmConfigFrom", () => {
  test("defaults to the public registry", () => {
    expect(npmConfigFrom()).toEqual({ registry: NPM_REGISTRY, scopes: {}, auth: [] });
  });

  test("reads registry, scoped registries, and registry-scoped credentials; later layers win", () => {
    const cfg = npmConfigFrom(
      new Map([["registry", "https://old.example.com"], ["//npm.example.com/:_authToken", "user-token"]]),
      new Map([
        ["registry", "https://npm.example.com/repo"],
        ["@corp:registry", "https://corp.example.com/npm"],
        ["//npm.example.com/:_authToken", "project-token"],
        ["//corp.example.com/npm/:_auth", "dXNlcjpwYXNz"],
        ["//corp.example.com/npm/:email", "ignored@example.invalid"],
        ["_authToken", "unscoped-tokens-are-ignored"],
      ]),
    );
    expect(cfg.registry).toBe("https://npm.example.com/repo/");
    expect(cfg.scopes).toEqual({ "@corp": "https://corp.example.com/npm/" });
    expect(cfg.auth.map((a) => a.prefix)).toEqual(["//npm.example.com/", "//corp.example.com/npm/"]);
    expect(authHeaderFor(cfg, "https://npm.example.com/repo/pkg")).toBe("Bearer project-token");
    expect(authHeaderFor(cfg, "https://corp.example.com/npm/@corp%2fx")).toBe("Basic dXNlcjpwYXNz");
  });
});

describe("authHeaderFor", () => {
  const cfg = npmConfigFrom(
    new Map([
      ["//r.example.com/:_authToken", "host-token"],
      ["//r.example.com/private/:_authToken", "path-token"],
    ]),
  );

  test("uses the longest matching prefix", () => {
    expect(authHeaderFor(cfg, "https://r.example.com/private/pkg")).toBe("Bearer path-token");
    expect(authHeaderFor(cfg, "https://r.example.com/public/pkg")).toBe("Bearer host-token");
  });

  test("never sends credentials to another host, port, or scheme", () => {
    expect(authHeaderFor(cfg, "https://evil.example.com/r.example.com/")).toBeUndefined();
    expect(authHeaderFor(cfg, "https://r.example.com.evil.example/pkg")).toBeUndefined();
    expect(authHeaderFor(cfg, "https://r.example.com:8443/pkg")).toBeUndefined();
    expect(authHeaderFor(cfg, "file://r.example.com/pkg")).toBeUndefined();
    expect(authHeaderFor(cfg, "not a url")).toBeUndefined();
  });
});

test("registryFor honours @scope:registry", () => {
  const cfg = npmConfigFrom(new Map([["@corp:registry", "https://corp.example.com/"]]));
  expect(registryFor(cfg, "@corp/pkg")).toBe("https://corp.example.com/");
  expect(registryFor(cfg, "@other/pkg")).toBe(NPM_REGISTRY);
  expect(registryFor(cfg, "corp")).toBe(NPM_REGISTRY);
});

test("nerfDart drops the scheme, query, and last path segment", () => {
  expect(nerfDart("https://r.example.com:8080/a/b/?x=1")).toBe("//r.example.com:8080/a/b/");
  expect(nerfDart("https://registry.npmjs.org/")).toBe("//registry.npmjs.org/");
});

describe("loadNpmConfig", () => {
  let dir: string;
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  test("project .npmrc overrides the user .npmrc, and npm_config_registry overrides both", async () => {
    dir = await mkdtemp(join(tmpdir(), "depward-npmrc-"));
    const home = join(dir, "home");
    const project = join(dir, "project");
    await mkdir(home);
    await mkdir(project);
    await writeFile(join(home, ".npmrc"), "registry=https://user.example.com/\n//user.example.com/:_authToken=${NPM_TOKEN}\n");
    await writeFile(join(project, ".npmrc"), "@corp:registry=https://corp.example.com/\n");

    const cfg = await loadNpmConfig({ cwd: project, home, env: { NPM_TOKEN: "secret-value" } });
    expect(cfg.registry).toBe("https://user.example.com/");
    expect(cfg.scopes).toEqual({ "@corp": "https://corp.example.com/" });
    expect(authHeaderFor(cfg, "https://user.example.com/x")).toBe("Bearer secret-value");

    const overridden = await loadNpmConfig({ cwd: project, home, env: { npm_config_registry: "https://env.example.com" } });
    expect(overridden.registry).toBe("https://env.example.com/");
  });

  test("missing files fall back to defaults", async () => {
    dir = await mkdtemp(join(tmpdir(), "depward-npmrc-"));
    expect(await loadNpmConfig({ cwd: dir, home: dir, env: {} })).toEqual({ registry: NPM_REGISTRY, scopes: {}, auth: [] });
  });
});

describe("Secret", () => {
  test("never reveals its value through string conversion, JSON, or inspect", () => {
    const s = new Secret("npm_abcdef");
    const cfg = npmConfigFrom(new Map([["//r.example.com/:_authToken", "npm_abcdef"]]));
    expect(`${s}`).toBe("[redacted]");
    expect(JSON.stringify({ s, cfg })).not.toContain("npm_abcdef");
    expect(inspect(cfg, { depth: 10 })).not.toContain("npm_abcdef");
    expect(s.reveal()).toBe("npm_abcdef");
  });

  test("redactUrl strips userinfo", () => {
    expect(redactUrl("https://user:pass@r.example.com/x")).toBe("https://r.example.com/x");
    expect(redactUrl("::")).toBe("<invalid url>");
  });
});
