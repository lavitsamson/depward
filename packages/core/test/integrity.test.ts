import { createHash } from "node:crypto";
import { expect, test } from "vitest";
import { isDepwardError, strongestHash, verifyIntegrity } from "../src/index.ts";

const data = new TextEncoder().encode("tarball bytes");
const sri = (alg: string, bytes: Uint8Array = data): string => `${alg}-${createHash(alg).update(bytes).digest("base64")}`;
const mismatch = (e: unknown): boolean => isDepwardError(e, "INTEGRITY_MISMATCH");

test("strongestHash prefers sha512 and ignores unknown algorithms and options", () => {
  expect(strongestHash(`sha1-abc ${sri("sha256")} md5-x ${sri("sha512")}?opt`)).toEqual({
    algorithm: "sha512",
    digest: sri("sha512").slice("sha512-".length),
  });
  expect(strongestHash("sha1-abc md5-x")).toBeNull();
});

test("verifyIntegrity accepts matching SRI and rejects mismatches", () => {
  expect(() => verifyIntegrity(data, { integrity: sri("sha512") })).not.toThrow();
  expect(() => verifyIntegrity(data, { integrity: sri("sha512", new Uint8Array([1])) })).toThrow();
  try {
    verifyIntegrity(data, { integrity: "sha512-AAAA" });
  } catch (e) {
    expect(mismatch(e)).toBe(true);
  }
});

test("a weak shasum never overrides a failing SRI hash", () => {
  const shasum = createHash("sha1").update(data).digest("hex");
  expect(() => verifyIntegrity(data, { integrity: sri("sha512", new Uint8Array([1])), shasum })).toThrow();
});

test("legacy versions without integrity fall back to sha1 shasum", () => {
  const shasum = createHash("sha1").update(data).digest("hex");
  expect(() => verifyIntegrity(data, { shasum })).not.toThrow();
  expect(() => verifyIntegrity(data, { shasum: "0".repeat(40) })).toThrow();
  let err: unknown;
  try {
    verifyIntegrity(data, {});
  } catch (e) {
    err = e;
  }
  expect(mismatch(err)).toBe(true);
});
