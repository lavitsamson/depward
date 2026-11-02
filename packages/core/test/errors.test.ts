import { expect, test } from "vitest";
import { DepwardError, isDepwardError } from "../src/index.ts";

test("DepwardError carries a code and a cause", () => {
  const cause = new Error("socket hang up");
  const err = new DepwardError("NETWORK", "registry request failed", { cause });
  expect(err).toBeInstanceOf(Error);
  expect(err.name).toBe("DepwardError");
  expect(err.code).toBe("NETWORK");
  expect(err.cause).toBe(cause);
  expect(isDepwardError(err)).toBe(true);
  expect(isDepwardError(err, "TIMEOUT")).toBe(false);
  expect(isDepwardError(cause)).toBe(false);
});
