// Test-only tar writer, so tar reader tests can build exact (and deliberately broken)
// archives without shelling out to `tar`.

export interface TarEntry {
  name: string;
  /** Typeflag: "0" file (default), "1" hardlink, "2" symlink, "5" dir, "x" pax, "g" global pax, "L" GNU long name. */
  type?: string;
  data?: Uint8Array | string;
  linkname?: string;
  mode?: number;
  /** ustar prefix field (joined to name with "/"). */
  prefix?: string;
  /** GNU magic ("ustar  \0") instead of POSIX ("ustar\000"). */
  gnu?: boolean;
  /** Override the size field (for truncation tests). */
  size?: number;
  /** Raw 12-byte size field (for base-256 tests). */
  rawSize?: Uint8Array;
  badChecksum?: boolean;
}

const enc = new TextEncoder();
const bytesOf = (d: Uint8Array | string | undefined): Uint8Array =>
  d === undefined ? new Uint8Array(0) : typeof d === "string" ? enc.encode(d) : d;

function writeString(buf: Uint8Array, offset: number, length: number, value: string): void {
  buf.set(enc.encode(value).subarray(0, length), offset);
}

function writeOctal(buf: Uint8Array, offset: number, length: number, value: number): void {
  writeString(buf, offset, length, `${value.toString(8).padStart(length - 1, "0")}\0`);
}

export function header(e: TarEntry): Uint8Array {
  const h = new Uint8Array(512);
  const data = bytesOf(e.data);
  writeString(h, 0, 100, e.name);
  writeOctal(h, 100, 8, e.mode ?? 0o644);
  writeOctal(h, 108, 8, 0);
  writeOctal(h, 116, 8, 0);
  if (e.rawSize) h.set(e.rawSize, 124);
  else writeOctal(h, 124, 12, e.size ?? data.byteLength);
  writeOctal(h, 136, 12, 1_577_836_800);
  h.fill(0x20, 148, 156);
  writeString(h, 156, 1, e.type ?? "0");
  writeString(h, 157, 100, e.linkname ?? "");
  if (e.gnu) writeString(h, 257, 8, "ustar  \0");
  else {
    writeString(h, 257, 6, "ustar\0");
    writeString(h, 263, 2, "00");
  }
  if (e.prefix) writeString(h, 345, 155, e.prefix);
  let sum = 0;
  for (const b of h) sum += b;
  if (e.badChecksum) sum += 1;
  writeString(h, 148, 8, `${sum.toString(8).padStart(6, "0")}\0 `);
  return h;
}

/** Builds a tar archive. `trailer: false` omits the two zero end blocks. */
export function tar(entries: TarEntry[], opts: { trailer?: boolean } = {}): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const e of entries) {
    const data = bytesOf(e.data);
    parts.push(header(e), data);
    const pad = (512 - (data.byteLength % 512)) % 512;
    parts.push(new Uint8Array(pad));
  }
  if (opts.trailer !== false) parts.push(new Uint8Array(1024));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}

/** Encodes pax records (`"<len> key=value\n"`, where len counts the whole record). */
export function pax(records: Record<string, string>): string {
  let out = "";
  for (const [k, v] of Object.entries(records)) {
    const body = ` ${k}=${v}\n`;
    let len = enc.encode(body).byteLength + 1;
    while (`${len}`.length + enc.encode(body).byteLength !== len) len++;
    out += `${len}${body}`;
  }
  return out;
}
