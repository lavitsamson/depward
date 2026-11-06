import { describe, expect, test } from "vitest";
import { httpGet } from "../src/registry/http.ts";
import { isDepwardError } from "../src/index.ts";

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;

function fakeFetch(handler: Handler): { fetch: typeof fetch; seen: { url: string; auth: string | null }[] } {
  const seen: { url: string; auth: string | null }[] = [];
  const f = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    seen.push({ url, auth: new Headers(init?.headers).get("authorization") });
    return handler(url, init ?? {});
  };
  return { fetch: f as typeof fetch, seen };
}

const base = { timeoutMs: 1000, maxBytes: 1024 };
const authFor = (u: string): string | undefined => (u.startsWith("https://r.example.com/") ? "Bearer t" : undefined);

describe("httpGet", () => {
  test("returns status, headers, and body", async () => {
    const { fetch } = fakeFetch(() => new Response("hello", { status: 200, headers: { etag: '"x"' } }));
    const res = await httpGet("https://r.example.com/a", { ...base, fetch });
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toBe('"x"');
    expect(new TextDecoder().decode(res.body)).toBe("hello");
  });

  test("follows redirects, asking for credentials again on each hop", async () => {
    const { fetch, seen } = fakeFetch((url) =>
      url.startsWith("https://r.example.com/")
        ? new Response(null, { status: 302, headers: { location: "https://cdn.example.net/blob" } })
        : new Response("ok"),
    );
    const res = await httpGet("https://r.example.com/pkg/-/pkg-1.0.0.tgz", { ...base, fetch, authFor });
    expect(res.url).toBe("https://cdn.example.net/blob");
    expect(seen).toEqual([
      { url: "https://r.example.com/pkg/-/pkg-1.0.0.tgz", auth: "Bearer t" },
      { url: "https://cdn.example.net/blob", auth: null },
    ]);
  });

  test("caps redirects", async () => {
    const { fetch } = fakeFetch(() => new Response(null, { status: 301, headers: { location: "/again" } }));
    await expect(httpGet("https://r.example.com/", { ...base, fetch, maxRedirects: 2 })).rejects.toSatisfy((e) =>
      isDepwardError(e, "NETWORK"),
    );
  });

  test("refuses non-http URLs, including redirects to them", async () => {
    const { fetch } = fakeFetch(() => new Response(null, { status: 302, headers: { location: "file:///etc/passwd" } }));
    await expect(httpGet("file:///etc/passwd", { ...base, fetch })).rejects.toSatisfy((e) => isDepwardError(e, "INVALID_ARGUMENT"));
    await expect(httpGet("https://r.example.com/", { ...base, fetch })).rejects.toSatisfy((e) =>
      isDepwardError(e, "INVALID_ARGUMENT"),
    );
  });

  test("enforces the body size limit by content-length and by streamed bytes", async () => {
    const declared = fakeFetch(() => new Response("x", { headers: { "content-length": "999999" } }));
    await expect(httpGet("https://r.example.com/", { ...base, fetch: declared.fetch })).rejects.toSatisfy((e) =>
      isDepwardError(e, "LIMIT_EXCEEDED"),
    );
    const streamed = fakeFetch(() => new Response(new Uint8Array(2048)));
    await expect(httpGet("https://r.example.com/", { ...base, fetch: streamed.fetch })).rejects.toSatisfy((e) =>
      isDepwardError(e, "LIMIT_EXCEEDED"),
    );
  });

  test("times out with a TIMEOUT error", async () => {
    const { fetch } = fakeFetch(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
        }),
    );
    await expect(httpGet("https://r.example.com/", { ...base, timeoutMs: 20, fetch })).rejects.toSatisfy((e) =>
      isDepwardError(e, "TIMEOUT"),
    );
  });

  test("wraps network failures without leaking URL credentials", async () => {
    const { fetch } = fakeFetch(() => {
      throw new TypeError("fetch failed");
    });
    const err: unknown = await httpGet("https://u:secret@r.example.com/", { ...base, fetch }).catch((e: unknown) => e);
    expect(isDepwardError(err, "NETWORK")).toBe(true);
    expect((err as Error).message).not.toContain("secret");
  });
});
