import { describe, expect, test } from "vitest";
import { locateEntry } from "../src/lockfile/locate.ts";

const lines = (...l: string[]): string => `${l.join("\n")}\n`;

describe("locateEntry", () => {
  test("npm package-lock v3: the node_modules key whose version matches", () => {
    const text = lines(
      "{",
      '  "packages": {',
      '    "": { "name": "app" },',
      '    "node_modules/a/node_modules/foo": {',
      '      "version": "1.0.0"',
      "    },",
      '    "node_modules/foo": {',
      '      "version": "2.1.4",',
      '      "resolved": "https://registry.npmjs.org/foo/-/foo-2.1.4.tgz"',
      "    }",
      "  }",
      "}",
    );
    expect(locateEntry(text, "foo", "2.1.4")).toBe(7);
    expect(locateEntry(text, "foo", "1.0.0")).toBe(4);
  });

  test("npm: a name that is a suffix of another name does not match", () => {
    const text = lines('    "node_modules/xfoo": {', '      "version": "1.0.0"', "    },", '    "node_modules/foo": {', '      "version": "1.0.0"');
    expect(locateEntry(text, "foo", "1.0.0")).toBe(4);
  });

  test("pnpm v9: the packages key, not a peer suffix in importers", () => {
    const text = lines(
      "importers:",
      "  .:",
      "    dependencies:",
      "      foo:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0(react@18.0.0)",
      "packages:",
      "  '@scope/bar@3.0.0':",
      "    resolution: {integrity: sha512-x}",
      "  react@18.0.0:",
      "    resolution: {integrity: sha512-y}",
    );
    expect(locateEntry(text, "react", "18.0.0")).toBe(10);
    expect(locateEntry(text, "@scope/bar", "3.0.0")).toBe(8);
  });

  test("pnpm v6 and v5 keys", () => {
    expect(locateEntry(lines("packages:", "  /foo@1.2.3:", "    resolution: {}"), "foo", "1.2.3")).toBe(2);
    expect(locateEntry(lines("packages:", "  /@s/foo/1.2.3_react@18.0.0:", "    resolution: {}"), "@s/foo", "1.2.3")).toBe(2);
  });

  test("yarn classic and berry: the header followed by the version", () => {
    const classic = lines('"foo@^1.0.0", foo@^1.1.0:', '  version "1.1.2"', "", "bar-foo@^1.0.0:", '  version "1.1.2"');
    expect(locateEntry(classic, "foo", "1.1.2")).toBe(1);
    expect(locateEntry(classic, "bar-foo", "1.1.2")).toBe(4);
    const berry = lines('"@s/foo@npm:^2.0.0":', "  version: 2.0.1", "  resolution: x");
    expect(locateEntry(berry, "@s/foo", "2.0.1")).toBe(1);
  });

  test("bun.lock: the quoted name@version", () => {
    const text = lines("{", '  "packages": {', '    "foo": ["foo@1.0.0", "", {}, "sha512-x"],', "  }", "}");
    expect(locateEntry(text, "foo", "1.0.0")).toBe(3);
  });

  test("not found, or regex characters in the name, gives undefined", () => {
    expect(locateEntry(lines('"node_modules/foo": {', '"version": "1.0.0"'), "foo", "9.9.9")).toBeUndefined();
    expect(locateEntry(lines("  fooXjs@1.0.0:"), "foo.js", "1.0.0")).toBeUndefined();
  });
});
