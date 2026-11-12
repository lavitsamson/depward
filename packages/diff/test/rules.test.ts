import { readFileSync } from "node:fs";
import type { Finding, VersionMeta } from "@depward/core";
import { describe, expect, test } from "vitest";
import { DIFF_FINDING_IDS, diffPackages, diffRisk, isPatchBump, isRawIpEndpoint, MAX_EVIDENCE } from "../src/index.ts";
import { ATTESTED, attested, meta, packument, profile, type ProfileSpec } from "./helpers.ts";

const finding = (severity: Finding["severity"]): Finding => ({ id: "x", severity, package: "p", message: "", evidence: [], docsUrl: "" });

function findings(a: ProfileSpec, b: ProfileSpec, metaA?: VersionMeta, metaB?: VersionMeta): Finding[] {
  const va = a.version ?? "1.0.0";
  const vb = b.version ?? "1.1.0";
  return diffPackages(profile({ ...a, version: va }), profile({ ...b, version: vb }), metaA ?? meta(va), metaB ?? meta(vb)).findings;
}
const ids = (fs: Finding[]): string[] => fs.map((f) => `${f.id}:${f.severity}`);

describe("diff-new-install-script", () => {
  test("a new or changed install script is high; one finding covers all scripts", () => {
    const fs = findings({ scripts: { install: "node-gyp rebuild" } }, { scripts: { install: "node x.js", postinstall: "node y.js" } });
    expect(ids(fs)).toEqual(["diff-new-install-script:high"]);
    expect(fs[0]?.evidence.map((e) => e.detail)).toEqual(["was: node-gyp rebuild", "new script"]);
  });

  test("prepare and removed scripts are not flagged", () => {
    expect(findings({ scripts: { postinstall: "node a.js" } }, { scripts: { prepare: "tsc" } })).toEqual([]);
  });

  test("escapes control characters from the script", () => {
    const [f] = findings({}, { scripts: { postinstall: "node a.js\u001b[2K" } });
    expect(f?.evidence[0]?.snippet).toBe("postinstall: node a.js\\x1b[2K");
  });
});

describe("diff-new-capability and diff-new-network-in-non-network-pkg", () => {
  test.each([
    ["fs", "medium"],
    ["env", "medium"],
    ["child_process", "high"],
    ["dynamic_code", "high"],
    ["native_addon", "high"],
  ] as const)("new %s is %s", (cap, severity) => {
    expect(ids(findings({}, { caps: { [cap]: ["a.js"] } }))).toEqual([`diff-new-capability:${severity}`]);
  });

  test("new net is reported once, by the network rule", () => {
    const fs = findings({}, { caps: { net: ["a.js"] } });
    expect(ids(fs)).toEqual(["diff-new-network-in-non-network-pkg:high"]);
    expect(fs[0]?.evidence).toEqual([{ file: "a.js", line: 1, snippet: "use of net" }]);
  });

  test("a package that already used the network is not flagged", () => {
    expect(findings({ caps: { net: ["a.js"] } }, { caps: { net: ["b.js"] } })).toEqual([]);
  });

  test("evidence is capped", () => {
    const files = Array.from({ length: MAX_EVIDENCE + 3 }, (_, i) => `f${i}.js`);
    const [f] = findings({}, { caps: { fs: files } });
    expect(f?.evidence).toHaveLength(MAX_EVIDENCE + 1);
    expect(f?.evidence.at(-1)).toEqual({ detail: "and 3 more" });
  });
});

describe("diff-new-sensitive-env", () => {
  test("new sensitive keys are high; ordinary keys are not flagged", () => {
    expect(findings({ envKeys: ["HOME"] }, { envKeys: ["HOME", "DEBUG"] })).toEqual([]);
    const fs = findings({}, { envKeys: ["NPM_TOKEN", "DEBUG"] });
    expect(ids(fs)).toEqual(["diff-new-sensitive-env:high"]);
    expect(fs[0]?.message).toBe("newly reads sensitive environment variables (NPM_TOKEN)");
  });

  test("new enumeration of process.env is high", () => {
    const fs = findings({}, { signals: [{ id: "env-sensitive-read", detail: "enumerates process.env (Object.keys(process.env))" }] });
    expect(ids(fs)).toEqual(["diff-new-sensitive-env:high"]);
    expect(fs[0]?.evidence[0]?.detail).toMatch(/^enumerates process\.env/);
  });

  test("enumeration that A already did is not new", () => {
    const e = { id: "env-sensitive-read" as const, detail: "enumerates process.env (...process.env)" };
    expect(findings({ signals: [e] }, { signals: [{ ...e, file: "other.js" }] })).toEqual([]);
  });
});

describe("diff-new-endpoint", () => {
  test("new hostnames are medium, in one finding", () => {
    const fs = findings({ endpoints: ["https://a.example.com/"] }, { endpoints: ["https://a.example.com/", "https://b.example.com/x", "c.example.net"] });
    expect(ids(fs)).toEqual(["diff-new-endpoint:medium"]);
    expect(fs[0]?.message).toBe("2 new hardcoded endpoints");
  });

  test("a new raw IP makes it high and is listed first", () => {
    const fs = findings({}, { endpoints: ["https://a.example.com/", "http://192.0.2.7:8080/x"] });
    expect(ids(fs)).toEqual(["diff-new-endpoint:high"]);
    expect(fs[0]?.evidence[0]).toEqual({ snippet: "http://192.0.2.7:8080/x", detail: "raw IP" });
  });

  test.each([
    ["192.0.2.1", true],
    ["https://198.51.100.3/p", true],
    ["http://[2001:db8::1]:80/", true],
    ["2001:db8::2", true],
    ["https://example.com/", false],
    ["example.com", false],
    ["https://203.0.113.5.example.com/", false],
  ])("isRawIpEndpoint(%s) is %s", (e, want) => {
    expect(isRawIpEndpoint(e)).toBe(want);
  });
});

describe("diff-new-obfuscation", () => {
  test.each(["obfuscation", "encoded-payload"] as const)("a new %s signal is critical", (id) => {
    expect(ids(findings({}, { signals: [{ id }] }))).toEqual(["diff-new-obfuscation:critical"]);
  });

  test("obfuscation A already had is not new, even in another file", () => {
    expect(findings({ signals: [{ id: "obfuscation", file: "a.js" }] }, { signals: [{ id: "obfuscation", file: "b.js" }] })).toEqual([]);
  });
});

describe("diff-new-dependency", () => {
  test("each new dependency is a low finding", () => {
    const fs = findings({}, {}, meta("1.0.0", { dependencies: { a: "1" } }), meta("1.1.0", { dependencies: { a: "2", b: "1", c: "1" } }));
    expect(ids(fs)).toEqual(["diff-new-dependency:low", "diff-new-dependency:low"]);
    expect(fs.map((f) => f.message)).toEqual(["new dependency: b", "new dependency: c"]);
  });
});

describe("diff-publisher-changed", () => {
  test("without a packument, a different publisher is high", () => {
    const fs = findings({}, {}, meta("1.0.0"), meta("1.1.0", { _npmUser: { name: "mallory" } }));
    expect(ids(fs)).toEqual(["diff-publisher-changed:high"]);
    expect(fs[0]?.message).toBe("published by mallory, not by a recent publisher (alice)");
  });

  test("a trusted publish with provenance is exempt", () => {
    const b = meta("1.1.0", {
      _npmUser: { name: "GitHub Actions", trustedPublisher: { id: "github" } },
      dist: { tarball: "https://registry.example.invalid/t.tgz", attestations: ATTESTED },
    });
    expect(findings({}, {}, meta("1.0.0"), b)).toEqual([]);
  });

  test("with a packument, an established maintainer is not flagged", () => {
    const doc = packument([
      { v: "0.9.0", at: "2026-01-01T00:00:00Z", by: "alice", maintainers: ["alice", "bob"] },
      { v: "1.0.0", at: "2026-06-01T00:00:00Z", by: "alice", maintainers: ["alice", "bob"] },
      { v: "1.1.0", at: "2026-07-01T00:00:00Z", by: "bob", maintainers: ["alice", "bob"] },
    ]);
    const a = doc.versions["1.0.0"] as VersionMeta;
    const b = doc.versions["1.1.0"] as VersionMeta;
    const d = diffPackages(profile(), profile({ version: "1.1.0" }), a, b, { packument: doc });
    expect(d.publisherDelta).toEqual({ from: "alice", to: "bob" });
    expect(d.findings).toEqual([]);
    expect(diffPackages(profile(), profile({ version: "1.1.0" }), a, b).findings.map((f) => f.id)).toEqual(["diff-publisher-changed"]);
  });

  test("with a packument, an account new to the package is flagged", () => {
    const doc = packument([
      { v: "1.0.0", at: "2026-06-01T00:00:00Z", by: "alice", maintainers: ["alice"] },
      { v: "1.1.0", at: "2026-07-01T00:00:00Z", by: "mallory", maintainers: ["alice", "mallory"] },
    ]);
    const d = diffPackages(profile(), profile({ version: "1.1.0" }), doc.versions["1.0.0"] as VersionMeta, doc.versions["1.1.0"] as VersionMeta, { packument: doc });
    expect(ids(d.findings)).toEqual(["diff-publisher-changed:high"]);
  });
});

describe("diff-provenance-dropped", () => {
  test("losing attestations is high; gaining them is not a finding", () => {
    expect(ids(findings({}, {}, attested("1.0.0"), meta("1.1.0")))).toEqual(["diff-provenance-dropped:high"]);
    expect(findings({}, {}, meta("1.0.0"), attested("1.1.0"))).toEqual([]);
  });
});

describe("diff-semver-mismatch", () => {
  test("a patch that adds a capability or install script is medium", () => {
    expect(ids(findings({ version: "1.0.0" }, { version: "1.0.1", caps: { fs: ["a.js"] } }))).toEqual(["diff-new-capability:medium", "diff-semver-mismatch:medium"]);
    expect(ids(findings({ version: "1.0.0" }, { version: "1.0.1", scripts: { postinstall: "x" } }))).toEqual(["diff-new-install-script:high", "diff-semver-mismatch:medium"]);
  });

  test("a minor bump that adds a capability is not a mismatch", () => {
    expect(ids(findings({ version: "1.0.0" }, { version: "1.1.0", caps: { fs: ["a.js"] } }))).toEqual(["diff-new-capability:medium"]);
  });

  test.each([
    ["1.0.0", "1.0.1", true],
    ["0.0.3", "0.0.4", true],
    ["1.2.3", "1.2.10", true],
    ["1.0.1-beta.1", "1.0.2", true],
    ["1.0.0", "1.1.0", false],
    ["1.0.0", "2.0.0", false],
    ["1.0.1", "1.0.0", false],
    ["1.0.1-beta.1", "1.0.1", false],
    ["latest", "1.0.1", false],
  ])("isPatchBump(%s, %s) is %s", (from, to, want) => {
    expect(isPatchBump(from, to)).toBe(want);
  });
});

describe("risk", () => {

  test("is the highest severity, or info when there are no findings", () => {
    expect(diffRisk([])).toBe("info");
    expect(diffRisk([finding("low"), finding("medium")])).toBe("medium");
    expect(diffRisk([finding("high"), finding("medium")])).toBe("high");
  });

  test("two high findings escalate to critical", () => {
    expect(diffRisk([finding("high"), finding("high")])).toBe("critical");
  });

  test("findings are sorted by severity, then id", () => {
    const fs = findings({ version: "1.0.0" }, { version: "1.0.1", caps: { fs: ["a.js"], net: ["a.js"] }, signals: [{ id: "obfuscation" }] });
    expect(ids(fs)).toEqual(["diff-new-obfuscation:critical", "diff-new-network-in-non-network-pkg:high", "diff-new-capability:medium", "diff-semver-mismatch:medium"]);
  });
});

describe("finding catalog", () => {
  test("every diff finding ID has an entry in docs/findings.md", () => {
    const catalog = readFileSync(new URL("../../../docs/findings.md", import.meta.url), "utf8");
    for (const id of DIFF_FINDING_IDS) expect(catalog, id).toMatch(new RegExp(`^### ${id}\\r?$`, "m"));
  });
});
