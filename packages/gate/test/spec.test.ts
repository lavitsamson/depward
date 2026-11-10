import { describe, expect, test } from "vitest";
import { createPackageSpec, parsePackageSpec } from "../src/index.ts";

describe("parsePackageSpec: registry specs", () => {
  test.each([
    ["lodash", "lodash", "latest"],
    ["lodash@4.17.21", "lodash", "4.17.21"],
    ["lodash@^4", "lodash", "^4"],
    ["lodash@>=1 <2", "lodash", ">=1 <2"],
    ["lodash@", "lodash", "*"],
    ["@types/node", "@types/node", "latest"],
    ["@types/node@22", "@types/node", "22"],
    ["@scope/name@next", "@scope/name", "next"],
    ["left-pad@latest", "left-pad", "latest"],
    ["JSONStream", "JSONStream", "latest"],
  ])("%s → %s @ %s", (raw, name, range) => {
    expect(parsePackageSpec(raw)).toEqual({ source: "registry", raw, name, range });
  });

  test.each([
    ["my-lodash@npm:lodash@^4", "lodash", "^4", "my-lodash"],
    ["@me/x@npm:@real/y", "@real/y", "latest", "@me/x"],
    ["x@npm:y@", "y", "*", "x"],
  ])("alias %s checks the real package %s", (raw, name, range, alias) => {
    expect(parsePackageSpec(raw)).toEqual({ source: "registry", raw, name, range, alias });
  });
});

describe("parsePackageSpec: non-registry specs", () => {
  test.each([
    ["github:user/repo", "git"],
    ["gitlab:user/repo", "git"],
    ["bitbucket:user/repo", "git"],
    ["gist:abc123", "git"],
    ["user/repo", "git"],
    ["user/repo#main", "git"],
    ["git+https://github.com/u/r.git", "git"],
    ["git+ssh://git@github.com/u/r.git", "git"],
    ["git://github.com/u/r", "git"],
    ["git@github.com:u/r.git", "git"],
    ["https://github.com/u/r.git#v1", "git"],
    ["https://example.com/pkg.tgz", "url"],
    ["http://203.0.113.5/x.tgz", "url"],
    ["./local", "file"],
    ["../local", "file"],
    [".", "file"],
    ["/abs/path", "file"],
    ["~/pkg", "file"],
    ["file:../x", "file"],
    ["link:../x", "file"],
    ["pkg.tgz", "file"],
    ["../pkg-1.0.0.tar.gz", "file"],
    ["C:\\pkgs\\x", "file"],
    ["jsr:@std/path", "other"],
  ])("%s → %s", (raw, source) => {
    expect(parsePackageSpec(raw)).toEqual({ source, raw });
  });

  test.each([
    ["foo@github:u/r", "git"],
    ["foo@git+https://example.com/r.git", "git"],
    ["foo@https://example.com/f.tgz", "url"],
    ["foo@file:../foo", "file"],
    ["foo@workspace:*", "workspace"],
    ["@s/foo@workspace:^", "workspace"],
    ["foo@jsr:@std/x", "other"],
    ["foo@patch:foo@1#./p.patch", "other"],
  ])("aliased %s → %s", (raw, source) => {
    expect(parsePackageSpec(raw)).toMatchObject({ source, raw, alias: raw.slice(0, raw.indexOf("@", 1)) });
  });
});

describe("parsePackageSpec: invalid specs", () => {
  test.each(["", "foo bar", "foo;rm", "@scope", "@/x", "a@npm:", "a@npm:b@npm:c", "a@npm:github:u/r", "x".repeat(215)])(
    "%j is invalid",
    (raw) => {
      expect(parsePackageSpec(raw).source).toBe("invalid");
    },
  );
});

describe("createPackageSpec (npm init / create convention)", () => {
  test.each([
    ["vite", "create-vite"],
    ["vite@latest", "create-vite@latest"],
    ["@vitejs/app", "@vitejs/create-app"],
    ["@vitejs/app@2", "@vitejs/create-app@2"],
    ["@scope", "@scope/create"],
    ["@scope@1.0.0", "@scope/create@1.0.0"],
    ["user/template", "user/template"],
    ["./local-template", "./local-template"],
  ])("%s → %s", (input, mapped) => {
    expect(createPackageSpec(input)).toBe(mapped);
  });
});
