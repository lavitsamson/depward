import { expect, test } from "vitest";
import { EXIT, VERSION, main } from "../src/index.ts";

function run(argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = main(argv, { stdout: (s) => out.push(s), stderr: (s) => err.push(s) });
  return { code, out: out.join(""), err: err.join("") };
}

test("--version prints the version", () => {
  expect(run(["--version"])).toEqual({ code: EXIT.allow, out: `${VERSION}\n`, err: "" });
});

test("--help and no args print usage to stdout", () => {
  for (const argv of [["--help"], []]) {
    const r = run(argv);
    expect(r.code).toBe(EXIT.allow);
    expect(r.out).toContain("Usage: depward");
  }
});

test("unknown commands and flags are internal errors on stderr", () => {
  expect(run(["frobnicate"])).toMatchObject({ code: EXIT.error, out: "" });
  expect(run(["--nope"])).toMatchObject({ code: EXIT.error, out: "" });
  expect(run(["frobnicate"]).err).toContain("unknown command");
});
