import { isDepwardError } from "@depward/core";
import { describe, expect, test } from "vitest";
import { parseCapsLockfile, serializeCapsLockfile, splitKey, type CapsLockfile } from "../src/index.ts";

const SPEC_EXAMPLE = `{
  "version": 1,
  "packages": {
    "express@5.1.0": { "capabilities": ["fs", "net"], "approvedBy": "static", "approvedAt": "2026-11-02" },
    "left-pad@1.3.0": { "capabilities": [] }
  }
}`;

function invalid(text: string): string {
  try {
    parseCapsLockfile(text, "caps.json");
  } catch (err) {
    if (isDepwardError(err, "INVALID_LOCKFILE")) return err.message;
    throw err;
  }
  throw new Error("expected INVALID_LOCKFILE");
}

describe("splitKey", () => {
  test.each([
    ["left-pad@1.3.0", "left-pad", "1.3.0"],
    ["@scope/name@2.0.0-beta.1", "@scope/name", "2.0.0-beta.1"],
  ])("%s", (key, name, version) => {
    expect(splitKey(key)).toEqual({ name, version });
  });

  test.each(["left-pad", "@scope/name", "@1.0.0", "name@", ""])("%j is not a key", (key) => {
    expect(splitKey(key)).toBeNull();
  });
});

describe("parseCapsLockfile", () => {
  test("reads the spec example", () => {
    expect(parseCapsLockfile(SPEC_EXAMPLE)).toEqual({
      version: 1,
      packages: {
        "express@5.1.0": { capabilities: ["fs", "net"], approvedBy: "static", approvedAt: "2026-11-02" },
        "left-pad@1.3.0": { capabilities: [] },
      },
    });
  });

  test("keeps a reason", () => {
    const lock = parseCapsLockfile('{"version":1,"packages":{"a@1.0.0":{"capabilities":["net"],"approvedBy":"alice","approvedAt":"2026-11-13","reason":"telemetry opt-in"}}}');
    expect(lock.packages["a@1.0.0"]?.reason).toBe("telemetry opt-in");
  });

  test.each([
    ["not json", "{", "not valid JSON"],
    ["not an object", "[]", "must be a JSON object"],
    ["wrong version", '{"version":2,"packages":{}}', "unsupported version 2"],
    ["missing packages", '{"version":1}', '"packages" must be an object'],
    ["unknown top-level field", '{"version":1,"packages":{},"extra":true}', 'unknown field "extra"'],
    ["bad key", '{"version":1,"packages":{"left-pad":{"capabilities":[]}}}', 'invalid package key "left-pad"'],
    ["entry not an object", '{"version":1,"packages":{"a@1.0.0":[]}}', "a@1.0.0: must be an object"],
    ["capabilities missing", '{"version":1,"packages":{"a@1.0.0":{}}}', "a@1.0.0: capabilities must be an array"],
    ["capability not a name", '{"version":1,"packages":{"a@1.0.0":{"capabilities":["Net!"]}}}', 'a@1.0.0: invalid capability "Net!"'],
    ["duplicate capability", '{"version":1,"packages":{"a@1.0.0":{"capabilities":["fs","fs"]}}}', 'a@1.0.0: duplicate capability "fs"'],
    ["approvedBy not a string", '{"version":1,"packages":{"a@1.0.0":{"capabilities":[],"approvedBy":1}}}', "a@1.0.0: approvedBy must be a string"],
    ["approvedAt not a date", '{"version":1,"packages":{"a@1.0.0":{"capabilities":[],"approvedAt":"yesterday"}}}', "a@1.0.0: approvedAt must be a YYYY-MM-DD date"],
    ["unknown entry field", '{"version":1,"packages":{"a@1.0.0":{"capabilities":[],"ok":true}}}', 'a@1.0.0: unknown field "ok"'],
  ])("rejects %s", (_name, text, message) => {
    const got = invalid(text);
    expect(got).toContain("caps.json");
    expect(got).toContain(message);
  });

  test("names in messages are escaped", () => {
    expect(invalid('{"version":1,"packages":{"\\u001b[31mx":{"capabilities":[]}}}')).not.toContain("\u001b");
  });
});

describe("serializeCapsLockfile", () => {
  const lock: CapsLockfile = {
    version: 1,
    packages: {
      "zod@3.10.0": { capabilities: [] },
      "@scope/b@1.0.0": { reason: "why", approvedAt: "2026-11-13", approvedBy: "static", capabilities: ["net", "fs"] },
      "zod@3.9.0": { capabilities: ["env"], approvedBy: "static", approvedAt: "2026-11-13" },
      "a@1.0.0-beta.2": { capabilities: [] },
      "a@1.0.0": { capabilities: [] },
    },
  };

  test("sorts packages by name then semver, capabilities alphabetically, fields in a fixed order", () => {
    expect(serializeCapsLockfile(lock)).toMatchInlineSnapshot(`
      "{
        "version": 1,
        "packages": {
          "@scope/b@1.0.0": {
            "capabilities": [
              "fs",
              "net"
            ],
            "approvedBy": "static",
            "approvedAt": "2026-11-13",
            "reason": "why"
          },
          "a@1.0.0-beta.2": {
            "capabilities": []
          },
          "a@1.0.0": {
            "capabilities": []
          },
          "zod@3.9.0": {
            "capabilities": [
              "env"
            ],
            "approvedBy": "static",
            "approvedAt": "2026-11-13"
          },
          "zod@3.10.0": {
            "capabilities": []
          }
        }
      }
      "
    `);
  });

  test("round-trips", () => {
    const text = serializeCapsLockfile(lock);
    expect(serializeCapsLockfile(parseCapsLockfile(text))).toBe(text);
    const example = parseCapsLockfile(SPEC_EXAMPLE);
    expect(parseCapsLockfile(serializeCapsLockfile(example))).toEqual(example);
  });
});
