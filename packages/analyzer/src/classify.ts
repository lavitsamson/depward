// File classification by extension, shebang, and magic bytes. Pure; no parsing.

import type { FileKind } from "./types.ts";

/** The result of {@link classifyFile}. `format` names the binary format for native/wasm files. */
export interface Classification {
  kind: FileKind;
  format?: string;
}

const JS_EXT = /\.(?:js|cjs|mjs)$/i;
const SOURCE_EXT = /\.(?:ts|mts|cts|tsx|jsx)$/i;
const DECLARATION = /\.d\.(?:ts|mts|cts)$/i;

/** Classifies one package file. */
export function classifyFile(path: string, data: Uint8Array): Classification {
  const format = binaryFormat(data);
  if (format === "wasm" || /\.wasm$/i.test(path)) return { kind: "wasm", format: "wasm" };
  if (format) return { kind: "native", format };
  if (/\.node$/i.test(path)) return { kind: "native", format: "node addon" };
  if (JS_EXT.test(path)) return { kind: "js" };
  if (/\.json$/i.test(path)) return { kind: "json" };
  if (DECLARATION.test(path)) return { kind: "other" };
  if (SOURCE_EXT.test(path)) return { kind: "source" };
  if (!/\.[^/]*$/.test(basename(path)) && hasNodeShebang(data)) return { kind: "js" };
  return { kind: "other" };
}

function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

function hasNodeShebang(data: Uint8Array): boolean {
  if (data[0] !== 0x23 || data[1] !== 0x21) return false; // "#!"
  const end = data.indexOf(0x0a);
  const line = new TextDecoder().decode(data.subarray(0, end < 0 ? Math.min(data.length, 200) : Math.min(end, 200)));
  return /\bnode\b/.test(line);
}

const u32be = (d: Uint8Array, o: number): number =>
  (((d[o] ?? 0) << 24) | ((d[o + 1] ?? 0) << 16) | ((d[o + 2] ?? 0) << 8) | (d[o + 3] ?? 0)) >>> 0;
const u32le = (d: Uint8Array, o: number): number =>
  ((d[o] ?? 0) | ((d[o + 1] ?? 0) << 8) | ((d[o + 2] ?? 0) << 16) | ((d[o + 3] ?? 0) << 24)) >>> 0;

/** Detects ELF, Mach-O (thin and fat), PE, and wasm by magic bytes. */
export function binaryFormat(d: Uint8Array): string | undefined {
  if (d.length < 8) return undefined;
  const be = u32be(d, 0);
  if (be === 0x7f454c46) return "ELF";
  if (be === 0x0061736d) return "wasm";
  if (be === 0xfeedface || be === 0xfeedfacf || be === 0xcefaedfe || be === 0xcffaedfe) return "Mach-O";
  // 0xcafebabe is also a Java class file; Mach-O fat headers have a small arch count.
  if (be === 0xcafebabe && u32be(d, 4) > 0 && u32be(d, 4) < 20) return "Mach-O";
  if (d[0] === 0x4d && d[1] === 0x5a && d.length >= 0x40) {
    const peOffset = u32le(d, 0x3c);
    if (peOffset + 4 <= d.length && u32be(d, peOffset) === 0x50450000) return "PE";
  }
  return undefined;
}

/** Heuristic: a `.min.js` name, or code whose lines are very long on average. */
export function looksMinified(path: string, text: string): boolean {
  if (/\.min\.[cm]?js$/i.test(path)) return true;
  if (text.length < 512) return false;
  let lines = 1;
  for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) lines++;
  return text.length / lines > 250 || (lines <= 3 && text.length > 2000);
}

const BUNDLE_MARKERS = [
  "__webpack_require__",
  "__webpack_modules__",
  "__commonJS(",
  "__toESM(",
  "parcelRequire",
  "function r(e,n,t){function o(i,f){if(!n[i])", // browserify prelude
];

/** Heuristic: contains a well-known bundler runtime marker. */
export function looksBundled(text: string): boolean {
  return BUNDLE_MARKERS.some((m) => text.includes(m));
}
