import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { isDepwardError, parseLockfile, type DependencySource, type Lockfile } from "../src/index.ts";

const fixture = (rel: string): string => readFileSync(new URL(`../../../fixtures/lockfiles/${rel}`, import.meta.url), "utf8");

type Row = [source: DependencySource, dev: boolean | null, optional: boolean | null, hasIntegrity: boolean];

/** Compact view of a lockfile: key → [source, dev, optional, has integrity]. */
function table(lock: Lockfile): Record<string, Row> {
  return Object.fromEntries(
    [...lock.entries].map(([k, e]) => [k, [e.source, e.dev, e.optional, e.integrity !== null] satisfies Row]),
  );
}

/** A prod entry (dev and optional both false). */
const prodRow = (s: DependencySource, hasIntegrity = true): Row => [s, false, false, hasIntegrity];
/** An entry from a format that records neither dev nor optional. */
const nullRow = (s: DependencySource, hasIntegrity = true): Row => [s, null, null, hasIntegrity];

function errorCode(fn: () => unknown): string {
  try {
    fn();
    return "no error";
  } catch (e) {
    return isDepwardError(e) ? e.code : "not a DepwardError";
  }
}

const SHARED_REGISTRY = [
  "@sindresorhus/is@4.6.0",
  "ansi-regex@5.0.1",
  "debug@2.6.9",
  "emoji-regex@8.0.0",
  "is-fullwidth-code-point@3.0.0",
  "ms@2.0.0",
  "ms@2.1.3",
  "string-width@4.2.3",
  "strip-ansi@6.0.1",
];

describe("npm package-lock v3", () => {
  const lock = parseLockfile("package-lock.json", fixture("npm/package-lock.json"));

  test("normalizes every installed package", () => {
    expect(lock.format).toBe("npm");
    expect(table(lock)).toEqual({
      ...Object.fromEntries(SHARED_REGISTRY.map((k) => [k, prodRow("registry")])),
      "is-number@7.0.0": ["registry", true, false, true],
      "isarray@2.0.5": ["registry", false, true, true],
      "is-plain-obj@4.1.0": prodRow("git", false),
      "left-pad@1.3.0": prodRow("registry"),
      "local-lib@0.1.0": prodRow("link", false),
      "ws-a@0.2.0": prodRow("workspace", false),
    });
    expect(lock.findings).toEqual([]);
  });

  test("keeps resolved URLs and integrity, and resolves aliases to the real name", () => {
    expect(lock.entries.get("string-width@4.2.3")).toEqual({
      name: "string-width",
      version: "4.2.3",
      source: "registry",
      integrity: "sha512-wKyQRQpjJ0sIp62ErSZdGsjMJWsap5oRNihHhu6G7JVO/9jIB6UyevL+tXuOqrng8j/cxKTWyWUwvSTriiZz/g==",
      resolved: "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
      dev: false,
      optional: false,
    });
    expect(lock.entries.get("is-plain-obj@4.1.0")?.resolved).toBe(
      "git+ssh://git@github.com/sindresorhus/is-plain-obj.git#68e8cc77bb1bbd0bf7d629d3574b6ca70289b2cc",
    );
  });

  test("a package is prod if any copy is prod, and dev/optional only if every copy is", () => {
    const doc = {
      lockfileVersion: 3,
      packages: {
        "": { name: "root" },
        "node_modules/a": { version: "1.0.0", dev: true },
        "node_modules/b/node_modules/a": { version: "1.0.0" },
        "node_modules/c": { version: "1.0.0", devOptional: true },
        "node_modules/d": { version: "1.0.0", inBundle: true },
      },
    };
    const t = table(parseLockfile("package-lock.json", JSON.stringify(doc)));
    expect(t["a@1.0.0"]).toEqual(["registry", false, false, false]);
    expect(t["c@1.0.0"]).toEqual(["registry", false, false, false]);
    expect(t["d@1.0.0"]).toEqual(["bundled", false, false, false]);
  });

  test("lockfileVersion 1 is reported as unsupported, not misparsed", () => {
    const lock1 = parseLockfile("package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0" } } }));
    expect(lock1.entries.size).toBe(0);
    expect(lock1.findings.map((f) => [f.id, f.severity])).toEqual([["unsupported-lockfile", "info"]]);
  });
});

describe("pnpm-lock v9", () => {
  const lock = parseLockfile("pnpm-lock.yaml", fixture("pnpm-v9/pnpm-lock.yaml"));

  test("normalizes packages and derives dev/optional from importers and snapshots", () => {
    expect(lock.format).toBe("pnpm");
    expect(table(lock)).toEqual({
      ...Object.fromEntries(SHARED_REGISTRY.map((k) => [k, prodRow("registry")])),
      "is-number@7.0.0": ["registry", true, false, true],
      "isarray@2.0.5": ["registry", false, true, true],
      "is-plain-obj@4.1.0": prodRow("git"),
      "left-pad@1.3.0": prodRow("registry"),
      "local-lib@file:local-lib": ["file", false, false, false],
    });
  });

  test("git-hosted tarballs keep their URL", () => {
    expect(lock.entries.get("is-plain-obj@4.1.0")?.resolved).toBe(
      "https://codeload.github.com/sindresorhus/is-plain-obj/tar.gz/68e8cc77bb1bbd0bf7d629d3574b6ca70289b2cc",
    );
  });
});

describe("pnpm-lock v6", () => {
  test("normalizes packages, strips peer suffixes, and adds importer links", () => {
    const lock = parseLockfile("pnpm-lock.yaml", fixture("pnpm-v6/pnpm-lock.yaml"));
    expect(lock.format).toBe("pnpm");
    expect(table(lock)).toEqual({
      "debug@4.3.4": ["registry", false, false, true],
      "has-flag@4.0.0": ["registry", false, false, true],
      "isarray@2.0.5": ["registry", false, true, true],
      "ms@2.1.2": ["registry", false, false, true],
      "supports-color@8.1.1": ["registry", false, false, true],
      "local-lib@file:local-lib": ["file", false, false, false],
      "is-plain-obj@4.1.0": ["git", false, false, false],
      "ws-a@link:packages/ws-a": ["link", false, false, false],
    });
  });

  test("older formats are reported as unsupported", () => {
    const lock = parseLockfile("pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /a/1.0.0:\n    dev: false\n");
    expect(lock.entries.size).toBe(0);
    expect(lock.findings[0]?.id).toBe("unsupported-lockfile");
  });
});

describe("pnpm-lock with an env document (pnpm 11+)", () => {
  test("reads every YAML document; pnpm itself counts as a prod package", () => {
    const lock = parseLockfile("pnpm-lock.yaml", fixture("pnpm-v11-env/pnpm-lock.yaml"));
    expect(lock.format).toBe("pnpm");
    expect(table(lock)).toEqual({
      "@pnpm/exe.linux-x64@12.7.0": ["registry", false, true, true],
      "is-number@7.0.0": ["registry", true, false, true],
      "pnpm@12.7.0": ["registry", false, false, true],
    });
  });

  test("an unsupported version in any document makes the file unsupported", () => {
    const text = "---\nlockfileVersion: '9.0'\npackages: {}\n---\nlockfileVersion: 5.4\npackages: {}\n";
    expect(parseLockfile("pnpm-lock.yaml", text).findings[0]?.id).toBe("unsupported-lockfile");
  });
});

describe("yarn v1", () => {
  const lock = parseLockfile("yarn.lock", fixture("yarn-v1/yarn.lock"));

  test("normalizes entries; yarn v1 does not record dev/optional", () => {
    expect(lock.format).toBe("yarn-classic");
    expect(table(lock)).toEqual({
      ...Object.fromEntries(SHARED_REGISTRY.map((k) => [k, nullRow("registry")])),
      "is-number@7.0.0": nullRow("registry"),
      "isarray@2.0.5": nullRow("registry"),
      "is-plain-obj@4.1.0": nullRow("git", false),
      "left-pad@1.3.0": nullRow("tarball", false),
      "local-lib@0.1.0": nullRow("file", false),
    });
  });

  test("strips the sha1 fragment from registry URLs but keeps git commits", () => {
    expect(lock.entries.get("ms@2.1.3")?.resolved).toBe("https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz");
    expect(lock.entries.get("left-pad@1.3.0")?.resolved).toBe("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz");
  });

  test("handles multi-spec keys, escapes, and comments", () => {
    const text = [
      "# yarn lockfile v1",
      "",
      '"@a/b@^1.0.0", "@a/b@~1.2.0", alias@npm:@a/b@1.2.3:',
      '  version "1.2.3"',
      '  resolved "https://r.example.com/@a/b/-/b-1.2.3.tgz#0123456789abcdef0123456789abcdef01234567"',
      "  integrity sha512-AAAA",
      "  dependencies:",
      '    "dep" "^1"',
      "",
      '"quoted@1.0.0":',
      '  version "1.0.0"',
      '  resolved "https://r.example.com/x\\"y.tgz"',
      "",
    ].join("\n");
    const l = parseLockfile("yarn.lock", text);
    expect([...l.entries.keys()]).toEqual(["@a/b@1.2.3", "quoted@1.0.0"]);
    expect(l.entries.get("@a/b@1.2.3")?.integrity).toBe("sha512-AAAA");
    expect(l.entries.get("quoted@1.0.0")?.resolved).toBe('https://r.example.com/x"y.tgz');
  });
});

describe("yarn berry", () => {
  test("normalizes entries; checksums are not npm integrity so they are not reported", () => {
    const lock = parseLockfile("yarn.lock", fixture("yarn-berry/yarn.lock"));
    expect(lock.format).toBe("yarn-berry");
    expect(table(lock)).toEqual({
      ...Object.fromEntries(SHARED_REGISTRY.map((k) => [k, nullRow("registry", false)])),
      "is-number@7.0.0": nullRow("registry", false),
      "isarray@2.0.5": nullRow("registry", false),
      "is-plain-obj@4.1.0": nullRow("git", false),
      "left-pad@1.3.0": nullRow("tarball", false),
      "local-lib@0.1.0": nullRow("file", false),
      "ws-a@0.0.0-use.local": nullRow("workspace", false),
    });
    expect(lock.entries.get("is-plain-obj@4.1.0")?.resolved).toBe(
      "https://github.com/sindresorhus/is-plain-obj.git#commit=3b33a59bd31fdee17acebeb0f9e39b6eca007719",
    );
  });
});

describe("bun.lock", () => {
  test("normalizes the tuple layouts", () => {
    const lock = parseLockfile("bun.lock", fixture("bun/bun.lock"));
    expect(lock.format).toBe("bun");
    expect(table(lock)).toEqual({
      "@sindresorhus/is@4.6.0": nullRow("registry"),
      "debug@2.6.9": nullRow("registry"),
      "ms@2.0.0": nullRow("registry"),
      "ms@2.1.3": nullRow("registry"),
      "is-number@7.0.0": nullRow("registry"),
      "isarray@2.0.5": nullRow("registry"),
      "is-plain-obj@github:sindresorhus/is-plain-obj#68e8cc7": nullRow("git", false),
      "left-pad@https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz": nullRow("tarball"),
      "local-lib@file:local-lib": nullRow("file", false),
      "ws-a@workspace:packages/ws-a": nullRow("workspace", false),
    });
  });

  test("accepts comments and trailing commas, but not inside strings", () => {
    const text = `{ // c
      "lockfileVersion": 1, /* block */
      "packages": { "a": ["a@1.0.0", "", { "x": "// not a comment, }" }, "sha512-A",], },
    }`;
    const lock = parseLockfile("bun.lock", text);
    expect(lock.entries.get("a@1.0.0")?.integrity).toBe("sha512-A");
  });

  test("the binary bun.lockb is reported as unsupported", () => {
    const lock = parseLockfile("path/to/bun.lockb", "\u0000binary");
    expect(lock.format).toBeNull();
    expect(lock.findings).toEqual([
      expect.objectContaining({ id: "unsupported-lockfile", severity: "info", package: "path/to/bun.lockb" }),
    ]);
  });
});

describe("parseLockfile: errors and hostile input", () => {
  test("unknown file names are rejected", () => {
    expect(errorCode(() => parseLockfile("Cargo.lock", ""))).toBe("INVALID_ARGUMENT");
  });

  test.each([
    ["package-lock.json", "{not json"],
    ["package-lock.json", "[]"],
    ["pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: [1, 2]\n"],
    ["pnpm-lock.yaml", "a: [unclosed"],
    ["yarn.lock", "just some text\n"],
    ["bun.lock", "{"],
  ])("malformed %s → INVALID_LOCKFILE", (path, text) => {
    expect(errorCode(() => parseLockfile(path, text))).toBe("INVALID_LOCKFILE");
  });

  test("prototype-like keys are plain data", () => {
    const doc = { lockfileVersion: 3, packages: { "node_modules/__proto__": { version: "1.0.0" }, "node_modules/constructor": { version: "2.0.0" } } };
    const lock = parseLockfile("package-lock.json", JSON.stringify(doc));
    expect([...lock.entries.keys()].toSorted()).toEqual(["__proto__@1.0.0", "constructor@2.0.0"]);
    expect(({} as Record<string, unknown>)["version"]).toBeUndefined();
  });

  test("YAML alias bombs are refused", () => {
    const bomb = ["lockfileVersion: '9.0'", "a: &a [x, x, x, x, x, x, x, x, x, x]"];
    for (let i = 0; i < 12; i++) bomb.push(`${"b".repeat(i + 1)}: &${"b".repeat(i + 1)} [${Array(10).fill(i === 0 ? "*a" : `*${"b".repeat(i)}`).join(", ")}]`);
    expect(errorCode(() => parseLockfile("pnpm-lock.yaml", bomb.join("\n")))).toBe("INVALID_LOCKFILE");
  });

  test("huge inputs hit a size limit", () => {
    expect(errorCode(() => parseLockfile("package-lock.json", "x".repeat(11), { maxBytes: 10 }))).toBe("LIMIT_EXCEEDED");
  });
});
