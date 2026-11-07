import { readFileSync } from "node:fs";
import AjvModule from "ajv-draft-04";
import { describe, expect, test } from "vitest";
import {
  colorEnabled,
  escapeMarkdown,
  escapeUnsafe,
  findingDocsUrl,
  renderJson,
  renderMarkdown,
  renderReport,
  renderSarif,
  renderTerminal,
  REPORT_FORMATS,
  summaryText,
  type Finding,
} from "../src/index.ts";

// ajv-draft-04 is CommonJS; under nodenext its default import is the module object.
const Ajv = AjvModule.default;

const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e);

const finding = (f: Partial<Finding> & Pick<Finding, "id" | "severity" | "package">): Finding => ({
  message: "message",
  evidence: [],
  docsUrl: findingDocsUrl(f.id),
  ...f,
});

/** A realistic mix, including hostile package-controlled text. */
const FINDINGS: Finding[] = [
  finding({ id: "hardcoded-endpoint", severity: "info", package: "evil-pkg", version: "1.0.1", message: "contains hardcoded network endpoints",
    evidence: [{ file: "index.js", line: 3, snippet: "https://collect.example.invalid/e" }] }),
  finding({ id: "env-exfil-pattern", severity: "critical", package: "evil-pkg", version: "1.0.1",
    message: "reads sensitive environment variables and uses the network in the same file",
    evidence: [
      { file: "index.js", line: 2, detail: "enumerates process.env (JSON.stringify(process.env))" },
      { file: "index.js", line: 3, detail: "network: fetch" },
    ] }),
  finding({ id: "install-script", severity: "medium", package: "@scope/native", version: "2.0.0", message: "runs install scripts (install)",
    evidence: [{ file: "package.json", snippet: "node-gyp rebuild", detail: "install" }] }),
  finding({ id: "fs-sensitive-path", severity: "high", package: "evil-pkg", version: "1.0.1",
    message: `references ${ESC}[2Kcredential${ESC}[31m locations`,
    evidence: [
      { file: `lib/${RLO}txt.js`, line: 7, snippet: "~/.ssh/id_rsa | <script>alert(1)</script> `x` @octocat [a](https://x.example.invalid)", detail: "SSH keys\nsecond line" },
    ] }),
  finding({ id: "minified-only", severity: "info", package: "plain", message: "ships only minified code", evidence: [{ detail: "2 JS file(s), all minified" }] }),
];

const snap = (name: string): string => `./__snapshots__/report/${name}`;
const fp = (list: Finding[]): string[] => (JSON.parse(renderSarif(list)).runs[0].results as { partialFingerprints: { primaryLocationLineHash: string } }[]).map((r) => r.partialFingerprints.primaryLocationLineHash);

describe("summaryText", () => {
  test("counts by severity, most severe first", () => {
    expect(summaryText(FINDINGS)).toBe("5 findings (1 critical, 1 high, 1 medium, 2 info)");
    expect(summaryText([])).toBe("no findings");
    expect(summaryText(FINDINGS.slice(0, 1))).toBe("1 finding (1 info)");
  });
});

describe("escapeUnsafe", () => {
  test("makes ANSI, controls, and bidi overrides visible", () => {
    expect(escapeUnsafe(`a${ESC}[31mb\r\n${RLO}c`)).toBe("a\\x1b[31mb\\x0d\\x0a\\u202ec");
  });
  test("truncates by code point", () => {
    expect(escapeUnsafe("🙂🙂🙂", 2)).toBe("🙂…");
  });
});

describe("escapeMarkdown", () => {
  test("neutralizes HTML, links, mentions, and table pipes", () => {
    const out = escapeMarkdown("<b>x</b> [a](u) @user | *y*");
    expect(out).not.toMatch(/<b>|(?<!\\)\]\(|(?<!\\)\||@user/);
    expect(out).toContain("@&#8203;user");
  });
});

describe("colorEnabled", () => {
  test.each([
    [{}, true, true],
    [{}, false, false],
    [{}, undefined, false],
    [{ NO_COLOR: "1" }, true, false],
    [{ NO_COLOR: "" }, true, true],
    [{ NO_COLOR: "1", FORCE_COLOR: "1" }, true, false],
    [{ FORCE_COLOR: "1" }, false, true],
    [{ FORCE_COLOR: "0" }, true, false],
    [{ FORCE_COLOR: "false" }, true, false],
    [{ TERM: "dumb" }, true, false],
  ] as const)("%j tty=%s → %s", (env, tty, want) => {
    expect(colorEnabled(env, tty)).toBe(want);
  });
});

describe("terminal", () => {
  test("snapshot without color", async () => {
    const out = renderTerminal(FINDINGS);
    expect(out).not.toContain(ESC);
    expect(out).not.toContain(RLO);
    await expect(out).toMatchFileSnapshot(snap("terminal.txt"));
  });

  test("with color, the only escapes are our own SGR codes", () => {
    const out = renderTerminal(FINDINGS, { color: true });
    const escapes = out.split(ESC).slice(1).map((s) => /^\[[0-9;]*m/.exec(s)?.[0]);
    expect(escapes.every((e) => e !== undefined)).toBe(true);
    expect(out).toContain(`${ESC}[1;31mCRITICAL`);
    expect(out).not.toContain(`${ESC}[2K`);
  });

  test("each finding stays on its own lines", () => {
    const lines = renderTerminal(FINDINGS).split("\n");
    // One line per evidence entry (6 in total); the embedded newline is escaped.
    expect(lines.filter((l) => l.startsWith("    - ")).length).toBe(6);
    expect(lines.some((l) => l.includes("SSH keys\\x0asecond line"))).toBe(true);
  });
});

describe("markdown", () => {
  test("snapshot", async () => {
    await expect(renderMarkdown(FINDINGS)).toMatchFileSnapshot(snap("report.md"));
  });

  test("hostile text cannot inject HTML, links, or mentions", () => {
    const out = renderMarkdown(FINDINGS);
    expect(out).not.toContain("<script>");
    expect(out).not.toMatch(/@octocat|@scope/);
    expect(out).not.toContain("](https://x.example.invalid)");
    expect(out).not.toContain(ESC);
    // Every table row has exactly 5 unescaped pipes.
    for (const row of out.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| Risk"))) {
      expect(row.match(/(?<!\\)\|/g)).toHaveLength(5);
    }
  });

  test("critical and high packages start expanded", () => {
    const out = renderMarkdown(FINDINGS);
    expect(out).toContain("<details open><summary>🔴 <code>evil-pkg@&#8203;1.0.1</code>");
    expect(out).toContain("<details><summary>🟡 <code>@&#8203;scope/native@&#8203;2.0.0</code>");
    expect(out).toContain("<details><summary>⚪ <code>plain</code>");
  });

  test("non-https docs URLs are not linked", () => {
    const out = renderMarkdown([finding({ id: "x", severity: "low", package: "p", docsUrl: "javascript:alert(1)" })]);
    expect(out).not.toContain("href");
  });

  test("no findings", () => {
    expect(renderMarkdown([])).toBe("## depward: no findings\n");
  });
});

describe("json", () => {
  test("snapshot", async () => {
    await expect(renderJson(FINDINGS, { tool: { version: "0.1.0" } })).toMatchFileSnapshot(snap("report.json"));
  });

  test("round-trips the findings, sorted", () => {
    const parsed = JSON.parse(renderJson(FINDINGS)) as { summary: Record<string, number>; findings: Finding[] };
    expect(parsed.summary).toEqual({ total: 5, critical: 1, high: 1, medium: 1, low: 0, info: 2 });
    expect(parsed.findings.map((f) => f.id)).toEqual(["env-exfil-pattern", "fs-sensitive-path", "install-script", "hardcoded-endpoint", "minified-only"]);
    expect(parsed.findings[1]?.message).toContain(ESC);
  });
});

describe("sarif", () => {
  const schema = JSON.parse(readFileSync(new URL("../../../fixtures/schemas/sarif-schema-2.1.0.json", import.meta.url), "utf8")) as object;
  const validate = new Ajv({ strict: false, allErrors: true }).compile(schema);

  test("snapshot", async () => {
    await expect(renderSarif(FINDINGS, { tool: { version: "0.1.0" } })).toMatchFileSnapshot(snap("report.sarif"));
  });

  test.each([["findings", FINDINGS], ["no findings", []]] as const)("validates against the SARIF 2.1.0 schema (%s)", (_, list) => {
    const log = JSON.parse(renderSarif(list, { tool: { version: "0.1.0" } })) as unknown;
    expect(validate(log), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  test("meets GitHub's code scanning requirements", () => {
    const log = JSON.parse(renderSarif(FINDINGS, { locate: () => ({ uri: "pnpm-lock.yaml", line: 42 }) }));
    const run = log.runs[0];
    for (const rule of run.tool.driver.rules) {
      expect(rule.shortDescription.text).not.toBe("");
      expect(rule.fullDescription.text.length).toBeLessThanOrEqual(1024);
      expect(rule.help.text).not.toBe("");
    }
    const exfil = run.tool.driver.rules.find((r: { id: string }) => r.id === "env-exfil-pattern");
    expect(exfil.properties["security-severity"]).toBe("9.5");
    const info = run.tool.driver.rules.find((r: { id: string }) => r.id === "minified-only");
    expect(info.properties["security-severity"]).toBeUndefined();
    for (const r of run.results) {
      expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe("pnpm-lock.yaml");
      expect(r.locations[0].physicalLocation.region.startLine).toBe(42);
      expect(r.partialFingerprints.primaryLocationLineHash).toMatch(/^[0-9a-f]{16}:\d+$/);
      expect(run.tool.driver.rules[r.ruleIndex].id).toBe(r.ruleId);
    }
  });

  test("fingerprints are stable and distinct", () => {
    const a = fp(FINDINGS);
    expect(new Set(a).size).toBe(a.length);
    expect(fp(FINDINGS.toReversed())).toEqual(a);
  });
});

describe("all formats", () => {
  test.each(REPORT_FORMATS)("%s output does not depend on input order and ends with a newline", (format) => {
    const a = renderReport(format, FINDINGS);
    expect(renderReport(format, FINDINGS.toReversed())).toBe(a);
    expect(a.endsWith("\n")).toBe(true);
  });
});

test("SARIF text carries no raw control or bidi characters", () => {
  const out = renderSarif(FINDINGS);
  expect(out).not.toContain("\u001b");
  expect(out).not.toContain(RLO);
  expect(out).toContain("\\x1b[2K");
});
