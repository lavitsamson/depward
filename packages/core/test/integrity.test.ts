import { createHash } from "node:crypto";
import { expect, test } from "vitest";
import { compareIntegrity, isDepwardError, strongestHash, verifyIntegrity } from "../src/index.ts";

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

test("compareIntegrity agrees, disagrees, or has nothing to compare", () => {
  const other = new TextEncoder().encode("other bytes");
  expect(compareIntegrity(sri("sha512"), { integrity: sri("sha512") })).toBe(true);
  expect(compareIntegrity(sri("sha512", other), { integrity: sri("sha512") })).toBe(false);
  // Several hashes: every shared algorithm must agree.
  expect(compareIntegrity(`${sri("sha256")} ${sri("sha512", other)}`, { integrity: `${sri("sha256")} ${sri("sha512")}` })).toBe(false);
  expect(compareIntegrity(sri("sha256"), { integrity: sri("sha512") })).toBeNull();
  expect(compareIntegrity("garbage", { integrity: sri("sha512") })).toBeNull();
  // A lockfile sha1 against the registry's hex shasum.
  const hex = createHash("sha1").update(data).digest("hex");
  expect(compareIntegrity(sri("sha1"), { shasum: hex })).toBe(true);
  expect(compareIntegrity(sri("sha1", other), { shasum: hex })).toBe(false);
  expect(compareIntegrity(sri("sha512"), {})).toBeNull();
});
