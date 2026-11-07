import { describe, expect, test } from "vitest";
import { clean, countAsciiEscapes, findEndpoints, isEncodedBlob, isIgnoredHost, isSensitiveEnvKey, sensitivePath, shannonEntropy } from "../src/text.ts";

describe("clean", () => {
  test("strips ANSI escapes and control characters", () => {
    expect(clean("\u001b[31mred\u001b[0m\nnext\u0007")).toBe("red next ");
  });
  test("strips Unicode line separators", () => {
    expect(clean(`a${String.fromCharCode(0x2028)}b`)).toBe("a b");
  });
  test("truncates with an ellipsis", () => {
    expect(clean("abcdef", 4)).toBe("abc…");
  });
});

describe("shannonEntropy", () => {
  test("is 0 for empty and uniform strings", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaa")).toBe(0);
  });
  test("is log2(n) for n equally likely symbols", () => {
    expect(shannonEntropy("abcd")).toBeCloseTo(2);
  });
});

describe("isSensitiveEnvKey", () => {
  test.each(["NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "GITHUB_TOKEN", "GH_PAT", "CI_JOB_TOKEN", "db_password", "API_KEY", "npm_config__authToken", "npm_config_//registry.npmjs.org/:_authToken"])("%s is sensitive", (k) => {
    expect(isSensitiveEnvKey(k)).toBe(true);
  });
  test.each(["NODE_ENV", "HOME", "PORT", "DEBUG", "PATH", "npm_config_user_agent", "npm_package_config_libvips", "HIGH_WATER", "CHUNKS_NPM_DIR"])("%s is not", (k) => {
    expect(isSensitiveEnvKey(k)).toBe(false);
  });
});

describe("sensitivePath", () => {
  test.each([
    [".npmrc", "npm credentials"],
    ["~/.ssh/id_ed25519", "SSH keys"],
    ["C:\\Users\\x\\.aws\\credentials", "AWS credentials"],
    ["/home/x/.config/gh/hosts.yml", "GitHub CLI credentials"],
    ["AppData/Local/Google/Chrome/User Data/Default/Login Data", "browser profile"],
    ["Library/Ethereum/keystore", "wallet keystore"],
  ])("%s → %s", (s, what) => {
    expect(sensitivePath(s)).toBe(what);
  });
  test.each([".sshrc", "aws-sdk", "npmrc", "gh-pages", "config/ghost", ".config/ghost"])("%s is not sensitive", (s) => {
    expect(sensitivePath(s)).toBeNull();
  });
});

describe("findEndpoints", () => {
  test("normalizes URLs, dropping the query and a bare root path", () => {
    expect(findEndpoints("see https://Api.Example.invalid/v1/x?token=1 and http://cdn.example.invalid/").map((e) => e.endpoint)).toEqual([
      "https://api.example.invalid/v1/x",
      "http://cdn.example.invalid",
    ]);
  });
  test("whole-literal IPs, with or without a port", () => {
    expect(findEndpoints("192.0.2.1:8080")).toEqual([{ endpoint: "192.0.2.1:8080", host: "192.0.2.1", ip: true }]);
    expect(findEndpoints("2001:db8::1")[0]?.ip).toBe(true);
    expect(findEndpoints("[2001:db8::1]:443")[0]?.host).toBe("2001:db8::1");
  });
  test("an IP embedded in prose is not an endpoint", () => {
    expect(findEndpoints("version 1.2.3.4 of the thing")).toEqual([]);
  });
  test("bare hostnames need a common TLD unless in host context", () => {
    expect(findEndpoints("evil-cdn.top")).toHaveLength(1);
    expect(findEndpoints("lodash.get")).toEqual([]);
    expect(findEndpoints("api.example.invalid")).toEqual([]);
    expect(findEndpoints("api.example.invalid", true)).toHaveLength(1);
  });
  test("drops loopback, reserved, and documentation hosts", () => {
    for (const s of ["http://localhost:3000", "http://127.0.0.1", "https://example.com/a", "https://sub.example.org", "http://x.test", "http://www.w3.org/2000/svg", "0.0.0.0", "::1"]) {
      expect(findEndpoints(s), s).toEqual([]);
    }
    expect(isIgnoredHost("foo.localhost")).toBe(true);
    expect(isIgnoredHost("example.invalid")).toBe(false);
  });
});

describe("countAsciiEscapes", () => {
  test("counts only escapes of printable ASCII", () => {
    expect(countAsciiEscapes(String.raw`"\x68\x69\u0041\u{42}"`)).toBe(4);
    expect(countAsciiEscapes(String.raw`"\x00\u4e00\n"`)).toBe(0);
  });
});

describe("isEncodedBlob", () => {
  test("base64 and hex over the minimum length", () => {
    expect(isEncodedBlob("QUJD".repeat(300))).toBe(true);
    expect(isEncodedBlob("0a".repeat(600))).toBe(true);
    expect(isEncodedBlob("QUJD".repeat(10))).toBe(false);
    expect(isEncodedBlob("hello world, ".repeat(100))).toBe(false);
  });
});
