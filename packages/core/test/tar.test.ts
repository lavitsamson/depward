import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { describe, expect, test } from "vitest";
import { isDepwardError, readTarball, type DepwardErrorCode } from "../src/index.ts";
import { pax, tar, type TarEntry } from "./helpers/tar-builder.ts";

const FIXTURE_TGZ = readFileSync(new URL("../../../fixtures/registry/tarballs/depward-fixture-stable-2.0.0.tgz", import.meta.url));
const text = (b: Uint8Array | undefined): string => new TextDecoder().decode(b);
const tgz = (entries: TarEntry[], opts?: { trailer?: boolean }): Uint8Array => gzipSync(tar(entries, opts));
const paths = (bytes: Uint8Array): string[] => readTarball(bytes).files.map((f) => f.path);

function errorCode(fn: () => unknown): DepwardErrorCode | "no error" | "not a DepwardError" {
  try {
    fn();
    return "no error";
  } catch (e) {
    return isDepwardError(e) ? e.code : "not a DepwardError";
  }
}

describe("readTarball: formats", () => {
  test("reads a real gzip'd ustar archive made by GNU tar, stripping package/", () => {
    const pkg = readTarball(FIXTURE_TGZ);
    expect(pkg.files.map((f) => f.path)).toEqual(["index.js", "package.json"]);
    expect(JSON.parse(text(pkg.files.find((f) => f.path === "package.json")?.data))).toMatchObject({ name: "depward-fixture-stable" });
    expect(pkg.unpackedSize).toBe(109);
  });

  test("strips whatever the first path segment is (e.g. @types tarballs use the package name)", () => {
    expect(paths(tgz([{ name: "node/index.d.ts", data: "x" }, { name: "./node/fs.d.ts", data: "y" }]))).toEqual(["fs.d.ts", "index.d.ts"]);
  });

  test("joins the ustar prefix field", () => {
    expect(paths(tgz([{ name: "deep/file.js", prefix: "package/lib/very", data: "x" }]))).toEqual(["lib/very/deep/file.js"]);
  });

  test("pax path and linkpath override the header fields", () => {
    const long = `package/${"d/".repeat(80)}file.js`;
    const pkg = readTarball(
      tgz([
        { name: "PaxHeader", type: "x", data: pax({ path: long }) },
        { name: "truncated-name", data: "content" },
        { name: "PaxHeader", type: "x", data: pax({ linkpath: "file.js", path: "package/ünïcode-link" }) },
        { name: "x", type: "2", linkname: "ignored" },
      ]),
    );
    expect(pkg.files.map((f) => f.path)).toEqual([long.slice("package/".length)]);
    expect(text(pkg.files[0]?.data)).toBe("content");
    expect(pkg.links).toEqual([{ path: "ünïcode-link", target: "file.js", kind: "symlink" }]);
  });

  test("pax headers apply to one entry only; global pax headers are tolerated", () => {
    expect(
      paths(
        tgz([
          { name: "pax_global_header", type: "g", data: pax({ comment: "abc" }) },
          { name: "PaxHeader", type: "x", data: pax({ path: "package/renamed.js" }) },
          { name: "package/a.js", data: "1" },
          { name: "package/b.js", data: "2" },
        ]),
      ),
    ).toEqual(["b.js", "renamed.js"]);
  });

  test("GNU long names", () => {
    const long = `package/${"x".repeat(150)}.js`;
    expect(paths(tgz([{ name: "././@LongLink", type: "L", data: `${long}\0`, gnu: true }, { name: "short", data: "z", gnu: true }]))).toEqual([
      long.slice("package/".length),
    ]);
  });

  test("accepts an uncompressed tar, skips directories, records modes", () => {
    const pkg = readTarball(tar([{ name: "package/bin/", type: "5" }, { name: "package/bin/cli.js", data: "#!", mode: 0o755 }]));
    expect(pkg.files).toEqual([{ path: "bin/cli.js", mode: 0o755, data: new TextEncoder().encode("#!") }]);
  });

  test("tolerates a missing end-of-archive trailer", () => {
    expect(paths(tgz([{ name: "package/a.js", data: "1" }], { trailer: false }))).toEqual(["a.js"]);
  });

  test("records duplicate paths; the last entry wins, like extraction", () => {
    const pkg = readTarball(tgz([{ name: "package/a.js", data: "first" }, { name: "package/a.js", data: "second" }]));
    expect(pkg.files.map((f) => text(f.data))).toEqual(["second"]);
    expect(pkg.duplicates).toEqual(["a.js"]);
  });

  test("files are sorted by path for deterministic output", () => {
    expect(paths(tgz(["z.js", "a/b.js", "B.js", "a.js"].map((n) => ({ name: `package/${n}`, data: n }))))).toEqual(["B.js", "a.js", "a/b.js", "z.js"]);
  });
});

describe("readTarball: links", () => {
  test("records symlinks and hardlinks inside the package without following them", () => {
    const pkg = readTarball(
      tgz([
        { name: "package/lib/index.js", data: "x" },
        { name: "package/lib/alias.js", type: "2", linkname: "./index.js" },
        { name: "package/up.js", type: "2", linkname: "lib/../lib/index.js" },
        { name: "package/hard.js", type: "1", linkname: "package/lib/index.js" },
      ]),
    );
    expect(pkg.files.map((f) => f.path)).toEqual(["lib/index.js"]);
    expect(pkg.links).toEqual([
      { path: "hard.js", target: "lib/index.js", kind: "hardlink" },
      { path: "lib/alias.js", target: "./index.js", kind: "symlink" },
      { path: "up.js", target: "lib/../lib/index.js", kind: "symlink" },
    ]);
  });

  test.each([
    ["relative escape", "2", "../../etc/passwd"],
    ["escape from a subdir", "2", "../../../x"],
    ["absolute", "2", "/etc/passwd"],
    ["windows absolute", "2", "C:\\Windows\\system.ini"],
    ["backslash escape", "2", "..\\..\\x"],
    ["hardlink escape", "1", "package/../../x"],
    ["hardlink absolute", "1", "/etc/passwd"],
  ])("rejects a link that escapes the package: %s", (_label, type, linkname) => {
    expect(errorCode(() => readTarball(tgz([{ name: "package/sub/link", type, linkname }])))).toBe("UNSAFE_PATH");
  });
});

describe("readTarball: unsafe paths", () => {
  test.each([
    "package/../evil.js",
    "package/a/../../evil.js",
    "/etc/cron.d/x",
    "\\evil.js",
    "C:/evil.js",
    "package\\..\\..\\evil.js",
  ])("rejects %j", (name) => {
    expect(errorCode(() => readTarball(tgz([{ name, data: "x" }])))).toBe("UNSAFE_PATH");
  });

  // A ustar name field is NUL-terminated, so NUL and long traversal paths can only arrive via pax.
  test.each(["package/../../x", "package/a\0b.js", "/abs/x"])("a pax path cannot smuggle in %j", (path) => {
    const archive = tgz([{ name: "PaxHeader", type: "x", data: pax({ path }) }, { name: "package/ok.js", data: "x" }]);
    expect(errorCode(() => readTarball(archive))).toBe("UNSAFE_PATH");
  });
});

describe("readTarball: limits", () => {
  test("compressed size", () => {
    expect(errorCode(() => readTarball(FIXTURE_TGZ, { maxCompressedBytes: 100 }))).toBe("LIMIT_EXCEEDED");
  });

  test("uncompressed size (a gzip bomb stops at the limit)", () => {
    const bomb = tgz([{ name: "package/zeros", data: new Uint8Array(4 * 1024 * 1024) }]);
    expect(bomb.byteLength).toBeLessThan(10_000);
    expect(errorCode(() => readTarball(bomb, { maxUncompressedBytes: 1024 * 1024 }))).toBe("LIMIT_EXCEEDED");
  });

  test("entry count", () => {
    const many = tgz(Array.from({ length: 11 }, (_, i) => ({ name: `package/f${i}.js`, data: "x" })));
    expect(errorCode(() => readTarball(many, { maxEntries: 10 }))).toBe("LIMIT_EXCEEDED");
    expect(readTarball(many, { maxEntries: 11 }).files).toHaveLength(11);
  });

  test("a huge base-256 size field", () => {
    const rawSize = new Uint8Array(12);
    rawSize[0] = 0x80;
    rawSize[4] = 0x7f; // ~2^63 bytes
    expect(errorCode(() => readTarball(tgz([{ name: "package/x", rawSize }])))).toBe("LIMIT_EXCEEDED");
  });
});

describe("readTarball: corrupt input", () => {
  test("bad header checksum", () => {
    expect(errorCode(() => readTarball(tgz([{ name: "package/a.js", data: "x", badChecksum: true }])))).toBe("INVALID_ARCHIVE");
  });

  test("entry data truncated", () => {
    expect(errorCode(() => readTarball(tgz([{ name: "package/a.js", data: "x", size: 4096 }], { trailer: false })))).toBe("INVALID_ARCHIVE");
  });

  test("corrupt gzip stream", () => {
    const broken = gzipSync(tar([{ name: "package/a.js", data: "x" }])).slice(0, 30);
    expect(errorCode(() => readTarball(broken))).toBe("INVALID_ARCHIVE");
  });

  test("not a tar at all", () => {
    expect(errorCode(() => readTarball(gzipSync(new TextEncoder().encode("hello world".repeat(100)))))).toBe("INVALID_ARCHIVE");
  });

  test("an empty archive has no files", () => {
    expect(readTarball(gzipSync(new Uint8Array(1024)))).toEqual({ files: [], links: [], duplicates: [], unpackedSize: 0 });
  });
});
