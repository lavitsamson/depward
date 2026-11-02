import { expect, test } from "vitest";
import { compareFindings, compareSeverity, type Finding } from "../src/index.ts";

const f = (id: string, severity: Finding["severity"], pkg: string): Finding => ({
  id, severity, package: pkg, message: id, evidence: [], docsUrl: `https://example.invalid/${id}`,
});

test("compareSeverity orders most severe first", () => {
  expect((["low", "critical", "info", "high", "medium"] as const).toSorted(compareSeverity))
    .toEqual(["critical", "high", "medium", "low", "info"]);
});

test("findings sort by severity, then package, then id", () => {
  const sorted = [
    f("b-rule", "low", "a"),
    f("a-rule", "high", "z"),
    f("a-rule", "low", "a"),
    f("c-rule", "high", "m"),
    f("a-rule", "critical", "z"),
  ].toSorted(compareFindings);
  expect(sorted.map((x) => `${x.severity}:${x.package}:${x.id}`)).toEqual([
    "critical:z:a-rule",
    "high:m:c-rule",
    "high:z:a-rule",
    "low:a:a-rule",
    "low:a:b-rule",
  ]);
});

test("package and id comparison is locale-independent", () => {
  const sorted = [f("x", "info", "b"), f("x", "info", "B"), f("x", "info", "a")].toSorted(compareFindings);
  expect(sorted.map((x) => x.package)).toEqual(["B", "a", "b"]);
});
