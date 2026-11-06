// In-memory reader for npm package tarballs (gzip'd tar). Formats:
// - POSIX ustar and pax: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html
// - GNU long names (typeflag L/K): https://www.gnu.org/software/tar/manual/html_node/Standard.html
//
// Nothing is ever written to disk and links are never followed. Untrusted input:
// every size is bounded and every path is validated before it is returned.

import { gunzipSync } from "node:zlib";
import { posix } from "node:path";
import { DepwardError } from "./errors.ts";

/** Limits for {@link readTarball}. Exceeding one throws `LIMIT_EXCEEDED`. */
export interface TarLimits {
  /** Default 50 MB. */
  maxCompressedBytes?: number;
  /** Default 200 MB. Enforced while decompressing, so gzip bombs stop early. */
  maxUncompressedBytes?: number;
  /** Default 20,000 (headers, including directories and links). */
  maxEntries?: number;
}

/** A regular file from the package, with the leading `package/` segment removed. */
export interface PackageFile {
  path: string;
  mode: number;
  data: Uint8Array;
}

/** A symlink or hardlink. Recorded as metadata only; never followed. */
export interface PackageLink {
  path: string;
  /** Symlinks: the raw target, relative to the link's directory. Hardlinks: a package path. */
  target: string;
  kind: "symlink" | "hardlink";
}

/** The contents of a package tarball. */
export interface PackageFiles {
  /** Regular files, sorted by path (code-unit order). */
  files: PackageFile[];
  /** Links, sorted by path. */
  links: PackageLink[];
  /** Paths that appeared more than once (the last entry wins, as in extraction). */
  duplicates: string[];
  /** Sum of file sizes. */
  unpackedSize: number;
}

const BLOCK = 512;
const MAX_META_BYTES = 1024 * 1024; // pax / GNU long-name payloads

const tooBig = (what: string): DepwardError => new DepwardError("LIMIT_EXCEEDED", `tarball exceeds the ${what} limit`);
const invalid = (why: string): DepwardError => new DepwardError("INVALID_ARCHIVE", `invalid tarball: ${why}`);
const unsafe = (why: string): DepwardError => new DepwardError("UNSAFE_PATH", `unsafe tarball entry: ${why}`);

/**
 * Reads a package tarball in memory. Accepts gzip'd or plain tar. Throws a
 * {@link DepwardError} with `LIMIT_EXCEEDED`, `INVALID_ARCHIVE`, or `UNSAFE_PATH`
 * (absolute paths, `..`, or links that point outside the package).
 *
 * Verify integrity first ({@link verifyIntegrity}; `RegistryClient.tarball` already does).
 */
export function readTarball(bytes: Uint8Array, limits: TarLimits = {}): PackageFiles {
  const maxCompressed = limits.maxCompressedBytes ?? 50 * 1024 * 1024;
  const maxUncompressed = limits.maxUncompressedBytes ?? 200 * 1024 * 1024;
  const maxEntries = limits.maxEntries ?? 20_000;

  if (bytes.byteLength > maxCompressed) throw tooBig("compressed size");
  const tarBytes = bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzip(bytes, maxUncompressed) : bytes;
  if (tarBytes.byteLength > maxUncompressed) throw tooBig("uncompressed size");

  const files = new Map<string, PackageFile>();
  const links = new Map<string, PackageLink>();
  const duplicates = new Set<string>();
  let entries = 0;
  let pending: { path?: string; linkpath?: string } = {};

  for (let offset = 0; offset + BLOCK <= tarBytes.byteLength; ) {
    const h = tarBytes.subarray(offset, offset + BLOCK);
    if (h.every((b) => b === 0)) break; // end of archive
    if (++entries > maxEntries) throw tooBig("entry count");
    verifyChecksum(h);

    const type = String.fromCharCode(h[156] ?? 0);
    const size = parseSize(h.subarray(124, 136), maxUncompressed);
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > tarBytes.byteLength) throw invalid("entry data is truncated");
    const data = tarBytes.subarray(dataStart, dataEnd);
    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (type === "x" || type === "L" || type === "K") {
      if (size > MAX_META_BYTES) throw tooBig("metadata header size");
      if (type === "x") pending = { ...pending, ...parsePax(data) };
      else if (type === "L") pending.path = cString(data);
      else pending.linkpath = cString(data);
      continue;
    }
    if (type === "g") continue; // global pax header: nothing we use

    const rawPath = pending.path ?? headerPath(h);
    const rawLink = pending.linkpath ?? cString(h.subarray(157, 257));
    pending = {};
    const path = packagePath(rawPath);
    if (path === null) continue; // the root directory itself, or a file outside any directory

    if (type === "0" || type === "\0" || type === "7") {
      if (files.has(path) || links.has(path)) duplicates.add(path);
      links.delete(path);
      files.set(path, { path, mode: parseOctal(h.subarray(100, 108)) & 0o7777, data: data.slice() });
    } else if (type === "1" || type === "2") {
      const kind = type === "2" ? "symlink" : "hardlink";
      const target = kind === "symlink" ? checkSymlink(path, rawLink) : checkHardlink(rawLink);
      if (files.has(path) || links.has(path)) duplicates.add(path);
      files.delete(path);
      links.set(path, { path, target, kind });
    }
    // Directories, devices, and FIFOs carry no content worth analysing.
  }

  const fileList = sorted(files);
  return {
    files: fileList,
    links: sorted(links),
    duplicates: [...duplicates].toSorted(),
    unpackedSize: fileList.reduce((n, f) => n + f.data.byteLength, 0),
  };
}

function sorted<T extends { path: string }>(m: Map<string, T>): T[] {
  return [...m.values()].toSorted((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function gunzip(bytes: Uint8Array, maxOutputLength: number): Uint8Array {
  try {
    return gunzipSync(bytes, { maxOutputLength });
  } catch (err) {
    if ((err as { code?: unknown }).code === "ERR_BUFFER_TOO_LARGE") throw tooBig("uncompressed size");
    throw new DepwardError("INVALID_ARCHIVE", "invalid tarball: gzip stream is corrupt", { cause: err });
  }
}

function verifyChecksum(h: Uint8Array): void {
  const stored = parseOctal(h.subarray(148, 156));
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < BLOCK; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : (h[i] ?? 0);
    unsigned += b;
    signed += b > 127 ? b - 256 : b;
  }
  if (stored !== unsigned && stored !== signed) throw invalid("header checksum mismatch");
}

function cString(bytes: Uint8Array): string {
  const nul = bytes.indexOf(0);
  return new TextDecoder().decode(nul < 0 ? bytes : bytes.subarray(0, nul));
}

function parseOctal(field: Uint8Array): number {
  const s = cString(field).trim();
  if (s === "") return 0;
  if (!/^[0-7]+$/.test(s)) throw invalid("malformed numeric field");
  return Number.parseInt(s, 8);
}

/** Size field: octal, or GNU base-256 when the high bit of the first byte is set. */
function parseSize(field: Uint8Array, max: number): number {
  if (((field[0] ?? 0) & 0x80) === 0) {
    const n = parseOctal(field);
    if (n > max) throw tooBig("uncompressed size");
    return n;
  }
  if ((field[0] ?? 0) & 0x40) throw invalid("negative size");
  let n = (field[0] ?? 0) & 0x7f;
  for (let i = 1; i < field.length; i++) {
    n = n * 256 + (field[i] ?? 0);
    if (n > max) throw tooBig("uncompressed size");
  }
  return n;
}

function headerPath(h: Uint8Array): string {
  const name = cString(h.subarray(0, 100));
  // POSIX ustar ("ustar\0") has a 155-byte prefix; GNU ("ustar  ") uses that area for other data.
  const isPosix = cString(h.subarray(257, 263)) === "ustar" && h[262] === 0;
  const prefix = isPosix ? cString(h.subarray(345, 500)) : "";
  return prefix ? `${prefix}/${name}` : name;
}

/** Parses pax records (`"<len> key=value\n"`), keeping only `path` and `linkpath`. */
function parsePax(data: Uint8Array): { path?: string; linkpath?: string } {
  const out: { path?: string; linkpath?: string } = {};
  let i = 0;
  while (i < data.byteLength) {
    const space = data.indexOf(0x20, i);
    if (space < 0) break;
    const len = Number(new TextDecoder().decode(data.subarray(i, space)));
    if (!Number.isInteger(len) || len <= space - i || i + len > data.byteLength) throw invalid("malformed pax header");
    const record = new TextDecoder().decode(data.subarray(space + 1, i + len - 1));
    const eq = record.indexOf("=");
    if (eq > 0) {
      const key = record.slice(0, eq);
      if (key === "path" || key === "linkpath") out[key] = record.slice(eq + 1);
    }
    i += len;
  }
  return out;
}

/** Splits on `/` and `\`, rejecting NUL, absolute paths, drive letters, and `..`. */
function safeSegments(raw: string, what: string): string[] {
  if (raw.includes("\0")) throw unsafe(`${what} contains NUL`);
  if (/^(?:[/\\]|[A-Za-z]:)/.test(raw)) throw unsafe(`${what} is absolute`);
  const segs = raw.split(/[/\\]/).filter((s) => s !== "" && s !== ".");
  if (segs.includes("..")) throw unsafe(`${what} contains ".."`);
  return segs;
}

/** Package-relative path (first segment, usually `package/`, removed), or `null` for the root. */
function packagePath(raw: string): string | null {
  const segs = safeSegments(raw, "path");
  return segs.length > 1 ? segs.slice(1).join("/") : null;
}

function checkSymlink(path: string, target: string): string {
  if (target.includes("\0")) throw unsafe("symlink target contains NUL");
  if (/^(?:[/\\]|[A-Za-z]:)/.test(target)) throw unsafe("symlink target is absolute");
  const resolved = posix.normalize(posix.join(posix.dirname(path), target.replaceAll("\\", "/")));
  if (resolved === ".." || resolved.startsWith("../")) throw unsafe("symlink points outside the package");
  return target;
}

function checkHardlink(target: string): string {
  const path = packagePath(target);
  if (path === null) throw unsafe("hardlink target is not a package file");
  return path;
}
