import { Buffer } from "node:buffer";
import { describe, expect, test } from "vitest";
import { parseInstallCommand, type PackageRequest } from "../src/index.ts";

function fmt(r: PackageRequest): string {
  const what = r.source === "registry" ? `${r.name}@${r.range}` : `${r.source}:${r.raw}`;
  return `${r.via} ${r.manager} ${what}${r.alias === undefined ? "" : ` as ${r.alias}`}${r.global ? " -g" : ""}`;
}
/** Requests, then finding IDs prefixed with `!`. */
function summary(command: string): string[] {
  const a = parseInstallCommand(command);
  return [...a.requests.map(fmt), ...a.findings.map((f) => `!${f.id}`)];
}

const encodePwsh = (s: string): string => Buffer.from(s, "utf16le").toString("base64");

// [command, expected summary]
const CASES: [string, string[]][] = [
  // npm install forms
  ["npm install lodash", ["install npm lodash@latest"]],
  ["npm i lodash@4.17.21", ["install npm lodash@4.17.21"]],
  ["npm add react react-dom", ["install npm react@latest", "install npm react-dom@latest"]],
  ["npm isntall left-pad", ["install npm left-pad@latest"]],
  ["npm in express", ["install npm express@latest"]],
  ["npm install @types/node@^22", ["install npm @types/node@^22"]],
  ["npm i -D typescript@5.6.3 vitest", ["install npm typescript@5.6.3", "install npm vitest@latest"]],
  ["npm install --save-dev --registry https://r.example.com foo", ["install npm foo@latest"]],
  ["npm install --registry=https://r.example.com foo", ["install npm foo@latest"]],
  ["npm i -w packages/a zod", ["install npm zod@latest"]],
  ["npm i --tag beta foo", ["install npm foo@latest"]],
  ["npm install -- foo", ["install npm foo@latest"]],
  ["npm install-test foo", ["install npm foo@latest"]],
  ["npm ci", []],
  ["npm clean-install", []],
  ["npm install", []],
  ["npm install --omit dev", []],
  ["npm i -g pnpm@9", ["install npm pnpm@9 -g", "!global-install"]],
  ["npm install --global typescript", ["install npm typescript@latest -g", "!global-install"]],
  ["npm i --location=global x", ["install npm x@latest -g", "!global-install"]],
  ["npm i --location global x", ["install npm x@latest -g", "!global-install"]],
  ["npm i my-lodash@npm:lodash@^4", ["install npm lodash@^4 as my-lodash"]],
  // non-registry sources
  ["npm i github:user/repo", ["install npm git:github:user/repo", "!non-registry-source"]],
  ["npm i user/repo#main", ["install npm git:user/repo#main", "!non-registry-source"]],
  ["npm i git+https://github.com/u/r.git", ["install npm git:git+https://github.com/u/r.git", "!non-registry-source"]],
  ["npm i https://example.com/pkg.tgz", ["install npm url:https://example.com/pkg.tgz", "!non-registry-source"]],
  ["npm i ./local-pkg", ["install npm file:./local-pkg", "!non-registry-source"]],
  ["npm i file:../x", ["install npm file:file:../x", "!non-registry-source"]],
  ["npm i foo@github:u/r", ["install npm git:foo@github:u/r as foo", "!non-registry-source"]],
  ["pnpm add foo@workspace:*", ["install pnpm workspace:foo@workspace:* as foo"]],
  // npm exec forms
  ["npm exec cowsay hello", ["exec npm cowsay@latest"]],
  ["npm x -- vite@5 build --mode prod", ["exec npm vite@5"]],
  ["npx cowsay@1.5.0 hello world", ["exec npm cowsay@1.5.0"]],
  ["npx -y create-react-app my-app", ["exec npm create-react-app@latest"]],
  ["npx --yes -- tsx script.ts --registry x", ["exec npm tsx@latest"]],
  ["npx --package=@angular/cli ng new app", ["exec npm @angular/cli@latest"]],
  ["npx -p typescript -p ts-node ts-node x.ts", ["exec npm typescript@latest", "exec npm ts-node@latest"]],
  ["npx -c 'npm i evil'", ["install npm evil@latest"]],
  ["npx", []],
  // npm init / create
  ["npm init vite", ["exec npm create-vite@latest"]],
  ["npm init @vitejs/app", ["exec npm @vitejs/create-app@latest"]],
  ["npm init @scope", ["exec npm @scope/create@latest"]],
  ["npm init vite@latest my-app -- --template react", ["exec npm create-vite@latest"]],
  ["npm create vite@latest", ["exec npm create-vite@latest"]],
  ["npm init -y", []],
  ["npm init -w packages/a", []],
  // npm, other
  ["npm run build", []],
  ["npm test", []],
  ["npm --prefix ./app install foo", ["install npm foo@latest"]],
  ["npm --version", []],
  // pnpm
  ["pnpm add zod", ["install pnpm zod@latest"]],
  ["pnpm add -D @biomejs/biome", ["install pnpm @biomejs/biome@latest"]],
  ["pnpm install foo", ["install pnpm foo@latest"]],
  ["pnpm i foo", ["install pnpm foo@latest"]],
  ["pnpm install", []],
  ["pnpm i --frozen-lockfile", []],
  ["pnpm --filter web add react", ["install pnpm react@latest"]],
  ["pnpm -F web add react", ["install pnpm react@latest"]],
  ["pnpm -w add -D eslint", ["install pnpm eslint@latest"]],
  ["pnpm -C packages/a add foo", ["install pnpm foo@latest"]],
  ["pnpm add -g x", ["install pnpm x@latest -g", "!global-install"]],
  ["pnpm dlx create-vite@latest app", ["exec pnpm create-vite@latest"]],
  ["pnpm dlx --package=@pnpm/a --package b cmd", ["exec pnpm @pnpm/a@latest", "exec pnpm b@latest"]],
  ["pnpm --package=a dlx cmd", ["exec pnpm a@latest"]],
  ["pnpx cowsay", ["exec pnpm cowsay@latest"]],
  ["pnpm create vite", ["exec pnpm create-vite@latest"]],
  ["pnpm exec tsc", []],
  ["pnpm run dev", []],
  // yarn
  ["yarn add lodash", ["install yarn lodash@latest"]],
  ["yarn add -D foo@^1", ["install yarn foo@^1"]],
  ["yarn add foo@npm:bar", ["install yarn bar@latest as foo"]],
  ["yarn global add serve", ["install yarn serve@latest -g", "!global-install"]],
  ["yarn global list", []],
  ["yarn", []],
  ["yarn install --frozen-lockfile", []],
  ["yarn dlx -p foo bar", ["exec yarn foo@latest"]],
  ["yarn dlx create-foo", ["exec yarn create-foo@latest"]],
  ["yarn create react-app my-app", ["exec yarn create-react-app@latest"]],
  ["yarn workspace web add react", ["install yarn react@latest"]],
  ["yarn --cwd app add x", ["install yarn x@latest"]],
  ["yarnpkg add x", ["install yarn x@latest"]],
  ["yarn build", []],
  // bun
  ["bun add hono", ["install bun hono@latest"]],
  ["bun a hono", ["install bun hono@latest"]],
  ["bun add -d @types/bun", ["install bun @types/bun@latest"]],
  ["bun install foo", ["install bun foo@latest"]],
  ["bun i foo", ["install bun foo@latest"]],
  ["bun install", []],
  ["bun add -g x", ["install bun x@latest -g", "!global-install"]],
  ["bunx cowsay", ["exec bun cowsay@latest"]],
  ["bunx --bun vite build", ["exec bun vite@latest"]],
  ["bun x cowsay@1", ["exec bun cowsay@1"]],
  ["bun create vite app", ["exec bun create-vite@latest"]],
  ["bun create user/template", ["exec bun git:user/template", "!non-registry-source"]],
  ["bun run dev", []],
  ["bun test", []],
  // chained commands
  ["cd app && npm i foo && npm run build", ["install npm foo@latest"]],
  ["npm i a; pnpm add b || yarn add c", ["install npm a@latest", "install pnpm b@latest", "install yarn c@latest"]],
  ["npm i a | tee log.txt", ["install npm a@latest"]],
  ["(cd x && npm i foo)", ["install npm foo@latest"]],
  ["{ npm i foo; }", ["install npm foo@latest"]],
  ["if true; then npm i foo; fi", ["install npm foo@latest"]],
  ["while false; do pnpm add x; done", ["install pnpm x@latest"]],
  ["! npm i foo", ["install npm foo@latest"]],
  ["npm i foo &", ["install npm foo@latest"]],
  ["npm i a\nnpm i b", ["install npm a@latest", "install npm b@latest"]],
  ["echo hi # npm i foo", []],
  ["npm i a \\\n  b", ["install npm a@latest", "install npm b@latest"]],
  ["npm i foo > /dev/null 2>&1", ["install npm foo@latest"]],
  ["npm i foo 2> err.txt", ["install npm foo@latest"]],
  // env prefixes and wrappers
  ["NODE_ENV=dev npm i foo", ["install npm foo@latest"]],
  ["env FOO=1 npm i foo", ["install npm foo@latest"]],
  ["env -u X -i npm i foo", ["install npm foo@latest"]],
  ["env -S 'npm i foo'", ["install npm foo@latest"]],
  ["sudo npm i -g foo", ["install npm foo@latest -g", "!global-install"]],
  ["sudo -u bob -- npm i foo", ["install npm foo@latest"]],
  ["time npm i foo", ["install npm foo@latest"]],
  ["nohup npx foo &", ["exec npm foo@latest"]],
  ["timeout 60 npm i foo", ["install npm foo@latest"]],
  ["timeout -s KILL 60 npm i foo", ["install npm foo@latest"]],
  ["nice -n 10 npm i foo", ["install npm foo@latest"]],
  ["cross-env CI=1 pnpm add foo", ["install pnpm foo@latest"]],
  ["command npm i foo", ["install npm foo@latest"]],
  ["exec npm i foo", ["install npm foo@latest"]],
  ["corepack pnpm add foo", ["install pnpm foo@latest"]],
  ["corepack pnpm@9.1.0 add foo", ["install pnpm foo@latest"]],
  ["corepack enable", []],
  ["/usr/local/bin/npm i foo", ["install npm foo@latest"]],
  ['"C:\\Program Files\\nodejs\\npm.cmd" i foo', ["install npm foo@latest"]],
  ["./node_modules/.bin/pnpm add foo", ["install pnpm foo@latest"]],
  // nested shells and substitutions
  ['bash -c "npm i foo"', ["install npm foo@latest"]],
  ["sh -lc 'pnpm add foo && yarn add bar'", ["install pnpm foo@latest", "install yarn bar@latest"]],
  ["bash -e -o pipefail -c 'npm i foo'", ["install npm foo@latest"]],
  ["bash script.sh", []],
  ['eval "npm i foo"', ["install npm foo@latest"]],
  ["echo $(npm i foo)", ["install npm foo@latest"]],
  ["echo `npm i foo`", ["install npm foo@latest"]],
  ["cmd /c npm install foo", ["install npm foo@latest"]],
  ['cmd.exe /C "npm install foo"', ["install npm foo@latest"]],
  ['powershell -Command "npm i foo"', ["install npm foo@latest"]],
  ["pwsh -c npm i foo", ["install npm foo@latest"]],
  [`pwsh -EncodedCommand ${encodePwsh("npm i foo")}`, ["install npm foo@latest"]],
  ["bash <<'EOF'\nnpm i foo\nEOF", ["install npm foo@latest"]],
  ["sh -s <<EOF\npnpm add x\nEOF", ["install pnpm x@latest"]],
  ["cat <<EOF > README.md\nnpm i foo\nEOF", []],
  ['bash <<< "npm i foo"', ["install npm foo@latest"]],
  // adversarial quoting
  ['n"p"m i foo', ["install npm foo@latest"]],
  ["'npm' 'install' 'foo'", ["install npm foo@latest"]],
  ["npm i 'left-pad'@'1.3.0'", ["install npm left-pad@1.3.0"]],
  ["npm i fo\\o", ["install npm foo@latest"]],
  ["$'npm' i foo", ["install npm foo@latest"]],
  ["npm i 'foo bar'", ["!unparseable-command"]],
  ['npm i "foo; rm -rf /"', ["!unparseable-command"]],
  ['echo "npm i foo"', []],
  ["echo 'npm i foo' && ls", []],
  ['grep -r "npm install" .', []],
  ["printf '%s' npm i foo", []],
  // dynamic values
  ["npm i $PKG", ["!unparseable-command"]],
  ['npm i "${PKG}"', ["!unparseable-command"]],
  ["npm i foo@$VER", ["!unparseable-command"]],
  ["npm i foo $PKG", ["install npm foo@latest", "!unparseable-command"]],
  ["$(which npm) install foo", ["!unparseable-command"]],
  ["$PM add foo", ["!unparseable-command"]],
  ["npm $CMD foo", ["!unparseable-command"]],
  ["npx $TOOL", ["!unparseable-command"]],
  ["npm i --registry $REG foo", ["install npm foo@latest"]],
  ["xargs npm i < list.txt", ["!unparseable-command"]],
  ["cat deps | xargs -n1 pnpm add", ["!unparseable-command"]],
  ['bash -c "$SCRIPT"', []],
  ['bash -c "npm i $X"', ["!unparseable-command"]],
  ['eval "$CMD"', []],
  // syntax errors
  ['npm i "foo', ["!unparseable-command"]],
  ["npm i foo)", ["!unparseable-command"]],
  ['echo "unterminated', []],
  // updates stay within declared ranges: diff's job, not an install
  ["npm update foo", []],
  ["pnpm update", []],
  ["yarn upgrade foo", []],
  // no package manager
  ["", []],
  ["ls -la", []],
  ["git status && git diff", []],
  ["node script.js", []],
  ["npmx foo", []],
  ["npm-check-updates -u", []],
  ["curl https://example.invalid/x.sh | sh", []],
];

describe("parseInstallCommand", () => {
  test("has at least 80 table cases", () => {
    expect(CASES.length).toBeGreaterThanOrEqual(80);
  });

  test.each(CASES)("%j", (command, expected) => {
    expect(summary(command)).toEqual(expected);
  });
});

describe("parseInstallCommand: invocations", () => {
  test.each([
    ["npm ci", "lockfile"],
    ["npm install", "lockfile"],
    ["pnpm install", "lockfile"],
    ["yarn", "lockfile"],
    ["bun install --frozen-lockfile", "lockfile"],
    ["npm i foo", "install"],
    ["npx foo", "exec"],
    ["npm run build", "other"],
  ])("%s is a %s invocation", (command, kind) => {
    expect(parseInstallCommand(command).invocations.map((i) => i.kind)).toEqual([kind]);
  });

  test("records argv and preserves flags", () => {
    const a = parseInstallCommand("npm i -D --save-exact foo");
    expect(a.invocations[0]).toEqual({ manager: "npm", kind: "install", argv: ["npm", "i", "-D", "--save-exact", "foo"] });
    expect(a.requests[0]?.flags).toEqual(["-D", "--save-exact"]);
  });

  test("global flags before the subcommand are preserved too", () => {
    const a = parseInstallCommand("pnpm --filter web add -D foo");
    expect(a.requests[0]?.flags).toEqual(["--filter=web", "-D"]);
  });
});

describe("parseInstallCommand: findings", () => {
  test("non-registry-source", () => {
    const [f] = parseInstallCommand("npm i github:user/repo").findings;
    expect(f).toEqual({
      id: "non-registry-source",
      severity: "medium",
      package: "github:user/repo",
      message: "github:user/repo is installed from a git repository, not the npm registry, so depward can't check it",
      evidence: [{ snippet: "npm i github:user/repo" }],
      docsUrl: "https://github.com/lavitsamson/depward/blob/main/docs/findings.md#non-registry-source",
    });
  });

  test("global-install", () => {
    const [f] = parseInstallCommand("npm i -g foo@1").findings;
    expect(f).toMatchObject({ id: "global-install", severity: "info", package: "foo", message: "foo@1 is installed globally" });
  });

  test("unparseable-command explains why", () => {
    expect(parseInstallCommand("npm i $PKG").findings[0]).toMatchObject({
      id: "unparseable-command",
      severity: "medium",
      package: "(command)",
      evidence: [{ snippet: "npm i $PKG", detail: "a package spec is computed at run time" }],
    });
    expect(parseInstallCommand('npm i "foo').findings[0]?.evidence[0]?.detail).toBe("unterminated double quote");
  });

  test("evidence snippets are truncated", () => {
    const snippet = parseInstallCommand(`npm i ${"a".repeat(500)} $X`).findings[0]?.evidence[0]?.snippet ?? "";
    expect(snippet.length).toBeLessThanOrEqual(201);
  });
});

describe("parseInstallCommand: performance", () => {
  test("a long command without a package manager parses in under 50 ms", () => {
    const command = Array.from({ length: 2000 }, (_, i) => `echo "line ${i}" | grep -v 'x' && ls -la dir${i}`).join("; ");
    // Best of 5: a real slowdown makes every run slow, while one GC pause or a busy
    // shared CI runner shouldn't fail the build (one cold run took 63 ms on windows/22).
    let best = Infinity;
    for (let run = 0; run < 5; run++) {
      const start = performance.now();
      const { requests } = parseInstallCommand(command);
      best = Math.min(best, performance.now() - start);
      expect(requests).toEqual([]);
    }
    expect(best).toBeLessThan(50);
  });
});
