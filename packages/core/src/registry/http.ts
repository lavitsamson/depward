import { DepwardError } from "../errors.ts";
import { redactUrl } from "../secret.ts";

/** A fully buffered HTTP response. */
export interface HttpResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
  /** The final URL after redirects. */
  url: string;
}

/** Options for {@link httpGet}. */
export interface HttpGetOptions {
  fetch: typeof fetch;
  headers?: Record<string, string>;
  /**
   * Returns the `Authorization` header for a URL. It is asked again for every redirect
   * hop, so credentials never follow a redirect to a host they don't belong to.
   */
  authFor?: (url: string) => string | undefined;
  timeoutMs: number;
  maxBytes: number;
  maxRedirects?: number;
}

/**
 * GET a URL with a timeout covering the whole exchange (headers and body), a body-size
 * cap, and manual redirect handling. Only `http:` and `https:` URLs are allowed, because
 * URLs such as tarball locations come from untrusted registry metadata.
 */
export async function httpGet(url: string, opts: HttpGetOptions): Promise<HttpResponse> {
  const signal = AbortSignal.timeout(opts.timeoutMs);
  const maxRedirects = opts.maxRedirects ?? 5;
  let current = url;
  try {
    for (let hop = 0; ; hop++) {
      assertHttpUrl(current);
      const headers = new Headers(opts.headers);
      const auth = opts.authFor?.(current);
      if (auth) headers.set("authorization", auth);
      const res = await opts.fetch(current, { headers, signal, redirect: "manual" });

      if (res.status >= 300 && res.status < 400 && res.status !== 304) {
        await res.body?.cancel();
        const location = res.headers.get("location");
        if (!location) throw new DepwardError("INVALID_RESPONSE", `redirect without location from ${redactUrl(current)}`);
        if (hop >= maxRedirects) throw new DepwardError("NETWORK", `too many redirects from ${redactUrl(url)}`);
        current = new URL(location, current).href;
        continue;
      }
      const body = await readBody(res, opts.maxBytes, current);
      return { status: res.status, headers: res.headers, body, url: current };
    }
  } catch (err) {
    if (err instanceof DepwardError) throw err;
    if (signal.aborted) {
      throw new DepwardError("TIMEOUT", `request to ${redactUrl(current)} timed out after ${opts.timeoutMs} ms`, { cause: err });
    }
    throw new DepwardError("NETWORK", `request to ${redactUrl(current)} failed`, { cause: err });
  }
}

function assertHttpUrl(url: string): void {
  let protocol: string;
  try {
    protocol = new URL(url).protocol;
  } catch (cause) {
    throw new DepwardError("INVALID_ARGUMENT", "invalid URL", { cause });
  }
  if (protocol !== "https:" && protocol !== "http:") {
    throw new DepwardError("INVALID_ARGUMENT", `refusing to fetch a ${protocol} URL`);
  }
}

async function readBody(res: Response, maxBytes: number, url: string): Promise<Uint8Array> {
  const tooBig = (): DepwardError =>
    new DepwardError("LIMIT_EXCEEDED", `response from ${redactUrl(url)} is larger than ${maxBytes} bytes`);
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel();
    throw tooBig();
  }
  if (!res.body) return new Uint8Array(0);

  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw tooBig();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

/** Parses a JSON body, converting failures into an `INVALID_RESPONSE` error. */
export function parseJson(body: Uint8Array, what: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch (cause) {
    throw new DepwardError("INVALID_RESPONSE", `${what} is not valid JSON`, { cause });
  }
}
