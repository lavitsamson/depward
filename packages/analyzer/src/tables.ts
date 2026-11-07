// Lookup tables for the capability and signal rules (spec: analyzer.md).

import type { Capability } from "./types.ts";

export const MODULE_CAPS: Record<string, Capability> = {
  fs: "fs",
  http: "net",
  https: "net",
  http2: "net",
  net: "net",
  tls: "net",
  dgram: "net",
  dns: "net",
  child_process: "child_process",
  vm: "dynamic_code",
  worker_threads: "worker",
  cluster: "worker",
  crypto: "crypto",
  os: "os_info",
};
/** Well-known HTTP/WebSocket client packages: importing one counts as `net`. */
export const HTTP_CLIENTS: ReadonlySet<string> = new Set([
  "node-fetch", "axios", "got", "undici", "request", "superagent", "needle", "phin", "ky", "ofetch",
  "cross-fetch", "isomorphic-fetch", "ws", "socket.io-client", "make-fetch-happen", "minipass-fetch",
]);
export const NATIVE_LOADERS: ReadonlySet<string> = new Set(["bindings", "node-gyp-build", "node-gyp-build-optional-packages", "@mapbox/node-pre-gyp"]);
export const NET_MODULES: ReadonlySet<string> = new Set([...Object.keys(MODULE_CAPS).filter((m) => MODULE_CAPS[m] === "net"), ...HTTP_CLIENTS]);
export const GLOBAL_NET: ReadonlySet<string> = new Set(["fetch", "WebSocket", "XMLHttpRequest", "EventSource"]);
export const GLOBAL_OBJECTS: ReadonlySet<string> = new Set(["globalThis", "global", "window", "self"]);
export const ENUMERATORS: ReadonlySet<string> = new Set(["Object.keys", "Object.values", "Object.entries", "Object.getOwnPropertyNames", "Object.assign", "JSON.stringify"]);
export const WRITE_FNS: ReadonlySet<string> = new Set(["writeFile", "writeFileSync", "appendFile", "appendFileSync", "write", "writeSync"]);
export const BINDING_CAPS: Record<string, Capability> = {
  fs: "fs", spawn_sync: "child_process", process_wrap: "child_process",
  tcp_wrap: "net", udp_wrap: "net", tls_wrap: "net", cares_wrap: "net",
};
export const DECODE_ENCODINGS: ReadonlySet<string> = new Set(["base64", "base64url", "hex"]);
export const HEX_ID: RegExp = /^_0x[0-9a-f]{4,}$/i;
