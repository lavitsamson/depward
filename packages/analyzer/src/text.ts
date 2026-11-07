// Pure string helpers: entropy, endpoint extraction, sensitive-path matching, cleaning.

import { isIP } from "node:net";

// oxlint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
// C0/C1 controls plus the U+2028/U+2029 line separators (built from char codes so the
// source stays ASCII).
const CONTROL = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(0x1f, 0x7f)}-${String.fromCharCode(0x9f, 0x2028, 0x2029)}]+`, "g");

/** Strips ANSI escapes and control characters, collapses whitespace, and truncates. */
export function clean(s: string, max = 120): string {
  const out = s.replace(ANSI, "").replace(CONTROL, " ");
  return out.length > max ? `${out.slice(0, max - 1)}…` : out;
}

/** Shannon entropy in bits per character (UTF-16 code units). */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<number, number>();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// The secret words match in any case. The vendor prefixes match only uppercase, at the
// start of the name: npm injects lowercase `npm_config_*` / `npm_package_*` variables
// that are configuration, not credentials (`npm_config__authToken` still matches TOKEN),
// and an unanchored `GH_` would match names such as `HIGH_WATER`.
const SECRET_WORD = /TOKEN|SECRET|KEY|PASSWORD/i;
const VENDOR_PREFIX = /^(?:NPM_|AWS_|GITHUB_|GH_|CI_JOB)/;

/** True for env var names that usually hold credentials (spec: `env-sensitive-read`). */
export function isSensitiveEnvKey(key: string): boolean {
  return SECRET_WORD.test(key) || VENDOR_PREFIX.test(key);
}

// Each rule is a sequence of path segments that must appear consecutively (case-insensitive).
const SENSITIVE_PATHS: { what: string; segments: string[] }[] = [
  { what: "npm credentials", segments: [".npmrc"] },
  { what: "SSH keys", segments: [".ssh"] },
  { what: "SSH keys", segments: ["id_rsa"] },
  { what: "SSH keys", segments: ["id_ed25519"] },
  { what: "AWS credentials", segments: [".aws"] },
  { what: "git credentials", segments: [".git-credentials"] },
  { what: "GitHub CLI credentials", segments: [".config", "gh"] },
  { what: "browser profile", segments: ["chrome", "user data"] },
  { what: "browser profile", segments: ["chromium", "user data"] },
  { what: "browser profile", segments: ["brave-browser", "user data"] },
  { what: "browser profile", segments: ["edge", "user data"] },
  { what: "browser profile", segments: [".config", "google-chrome"] },
  { what: "browser profile", segments: [".config", "chromium"] },
  { what: "browser profile", segments: [".mozilla", "firefox"] },
  { what: "browser profile", segments: ["firefox", "profiles"] },
  { what: "browser credentials", segments: ["login data"] },
  { what: "wallet keystore", segments: [".ethereum", "keystore"] },
  { what: "wallet keystore", segments: ["ethereum", "keystore"] },
  { what: "wallet keystore", segments: ["wallet.dat"] },
  { what: "wallet keystore", segments: [".electrum"] },
  { what: "wallet keystore", segments: [".solana", "id.json"] },
  { what: "wallet keystore", segments: ["exodus", "exodus.wallet"] },
  // MetaMask's Chrome extension ID (its vault lives under this directory).
  { what: "wallet keystore", segments: ["nkbihfbeogaeaoehlefnkodbefgpgknn"] },
];

/** Returns what kind of sensitive location a string literal points at, or `null`. */
export function sensitivePath(s: string): string | null {
  if (s.length > 4096) return null;
  const segs = s.toLowerCase().split(/[/\\]/);
  for (const rule of SENSITIVE_PATHS) {
    const n = rule.segments.length;
    for (let i = 0; i + n <= segs.length; i++) {
      if (rule.segments.every((seg, j) => segs[i + j] === seg)) return rule.what;
    }
  }
  return null;
}

// RFC 2606 / 6761 reserved names, plus hosts that appear in docs and XML namespaces.
const RESERVED_SUFFIXES = [".example", ".test", ".localhost", ".local"];
const IGNORED_HOSTS = new Set([
  "localhost",
  "example.com",
  "example.net",
  "example.org",
  "w3.org",
  "www.w3.org",
  "github.com",
  "www.github.com",
  "npmjs.com",
  "www.npmjs.com",
  "docs.npmjs.com",
  "nodejs.org",
  "developer.mozilla.org",
  "tc39.es",
  "json-schema.org",
  "opensource.org",
  "spdx.org",
  "tools.ietf.org",
  "datatracker.ietf.org",
  "www.rfc-editor.org",
  "schemas.xmlsoap.org",
  "schemas.microsoft.com",
  "purl.org",
  "xmlns.com",
  "mths.be",
  "en.wikipedia.org",
  "stackoverflow.com",
]);

/** True for loopback and unspecified addresses (`127.0.0.0/8`, `0.0.0.0`, `::1`, `::`). */
export function isLoopbackIp(ip: string): boolean {
  const v = ip.replace(/^\[|\]$/g, "");
  return v.startsWith("127.") || v === "0.0.0.0" || v === "::1" || v === "::";
}

/** True when a host should not be reported as an endpoint. */
export function isIgnoredHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (IGNORED_HOSTS.has(h) || isLoopbackIp(h)) return true;
  if (RESERVED_SUFFIXES.some((s) => h.endsWith(s))) return true;
  return /(?:^|\.)example\.(?:com|net|org)$/.test(h);
}

// TLDs that make a bare literal like "evil.top" plausibly a hostname rather than a file
// or property path. Hostnames used as a `host:`/`hostname:` value count regardless.
const HOST_TLDS = new Set(
  "com net org io dev app ru cn xyz top sh co me info biz cc tk pw su site online live cloud ws in to gg ly".split(" "),
);
const HOSTNAME = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})$/i;
const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'`<>()\\{}|^]+/gi;

/** An endpoint found in a string. `ip` is set when the host is an IP literal. */
export interface FoundEndpoint {
  /** Normalized: `scheme://host[:port]/path` for URLs, otherwise the host or IP. */
  endpoint: string;
  host: string;
  ip: boolean;
}

/**
 * Extracts endpoints from a string literal: URLs anywhere in it, or the whole literal
 * when it is an IP (optionally with a port) or a hostname with a common TLD. Set
 * `hostContext` when the literal is a `host`/`hostname` value, so any hostname counts.
 * Reserved, loopback, and documentation hosts are dropped.
 */
export function findEndpoints(s: string, hostContext = false): FoundEndpoint[] {
  if (s.length > 1_000_000) return [];
  const out: FoundEndpoint[] = [];
  for (const m of s.matchAll(URL_RE)) {
    let url: URL;
    try {
      url = new URL(m[0]);
    } catch {
      continue;
    }
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (!host || isIgnoredHost(host)) continue;
    const endpoint = `${url.protocol}//${url.host}${url.pathname === "/" ? "" : url.pathname}`;
    out.push({ endpoint: endpoint.slice(0, 200), host, ip: isIP(host) !== 0 });
  }
  if (out.length > 0) return out;

  const whole = s.trim();
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/.exec(whole)?.[1];
  const v6 = /^\[([0-9a-f:.]+)\](?::\d{1,5})?$/i.exec(whole)?.[1] ?? (isIP(whole) === 6 ? whole : undefined);
  const ip = v4 !== undefined && isIP(v4) === 4 ? v4 : v6 !== undefined && isIP(v6) === 6 ? v6 : undefined;
  if (ip !== undefined) return isLoopbackIp(ip) ? [] : [{ endpoint: whole, host: ip, ip: true }];
  const hm = HOSTNAME.exec(whole);
  if (hm && (hostContext || HOST_TLDS.has((hm[1] ?? "").toLowerCase())) && !isIgnoredHost(whole)) {
    out.push({ endpoint: whole.toLowerCase(), host: whole.toLowerCase(), ip: false });
  }
  return out;
}

/** Counts escapes (`\xNN`, `\uNNNN`, `\u{N}`) in raw literal source that decode to printable ASCII. */
export function countAsciiEscapes(raw: string): number {
  let n = 0;
  for (const m of raw.matchAll(/\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\})/g)) {
    const code = Number.parseInt(m[1] ?? m[2] ?? m[3] ?? "", 16);
    if (code >= 0x20 && code < 0x7f) n++;
  }
  return n;
}

const BASE64 = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX = /^(?:[0-9a-fA-F]{2})+$/;

/** True for a base64/base64url or hex literal (whitespace ignored) longer than `minLength`. */
export function isEncodedBlob(s: string, minLength = 1024): boolean {
  if (s.length <= minLength) return false;
  const compact = s.replace(/\s+/g, "");
  return compact.length > minLength && (HEX.test(compact) || BASE64.test(compact));
}
