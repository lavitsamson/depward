import { describe, expect, test } from "vitest";
import { parseShell, type ShellParse } from "../src/command/shell.ts";

/** Each simple command as its words; dynamic words are wrapped in `<…>`. */
function argvs(p: ShellParse): string[][] {
  return p.commands.map((c) => c.words.map((w) => (w.dynamic ? `<${w.text}>` : w.text)));
}
const parse = (s: string): string[][] => {
  const p = parseShell(s);
  expect(p.error).toBeUndefined();
  return argvs(p);
};

describe("parseShell: words and quoting", () => {
  test.each([
    ["npm i foo", [["npm", "i", "foo"]]],
    ["  npm\ti   foo  ", [["npm", "i", "foo"]]],
    ["'a b' \"c d\" e\\ f", [["a b", "c d", "e f"]]],
    ['n"p"m i fo\\o', [["npm", "i", "foo"]]],
    ["a '' \"\"", [["a", "", ""]]],
    ['echo "a \\" \\$ \\\\ \\x"', [["echo", 'a " $ \\ \\x']]],
    ["echo 'it''s'", [["echo", "its"]]],
    ["echo $'a\\tb\\'c'", [["echo", "a\tb'c"]]],
    ['echo $"hi"', [["echo", "hi"]]],
    ["a \\\n b", [["a", "b"]]],
    ["echo foo#bar # comment\nls", [["echo", "foo#bar"], ["ls"]]],
    ["echo $ x", [["echo", "$", "x"]]],
  ])("%j", (input, expected) => {
    expect(parse(input)).toEqual(expected);
  });
});

describe("parseShell: operators", () => {
  test.each([
    ["a && b || c ; d | e & f", [["a"], ["b"], ["c"], ["d"], ["e"], ["f"]]],
    ["a&&b||c;d|e", [["a"], ["b"], ["c"], ["d"], ["e"]]],
    ["a |& b", [["a"], ["b"]]],
    ["a\nb\r\nc", [["a"], ["b"], ["c"]]],
    ["(cd x && npm i foo)", [["cd", "x"], ["npm", "i", "foo"]]],
    ["((a) ; (b))", [["a"], ["b"]]],
    ["{ a; }", [["{", "a"], ["}"]]],
  ])("%j", (input, expected) => {
    expect(parse(input)).toEqual(expected);
  });
});

describe("parseShell: redirections", () => {
  test.each([
    ["npm i foo > /dev/null 2>&1", [["npm", "i", "foo"]]],
    ["npm i foo &> log", [["npm", "i", "foo"]]],
    ["npm i foo &>> log", [["npm", "i", "foo"]]],
    ["npm i foo 2> err.txt bar", [["npm", "i", "foo", "bar"]]],
    ["npm i foo >log <in >>app 2>|x", [["npm", "i", "foo"]]],
    ["a 2foo", [["a", "2foo"]]],
    ['a "2">x', [["a", "2"]]],
  ])("%j", (input, expected) => {
    expect(parse(input)).toEqual(expected);
  });

  test("heredoc bodies are attached as stdin, not parsed as commands", () => {
    const p = parseShell("cat <<'EOF' > out && ls\nnpm i foo\nEOF\necho done");
    expect(argvs(p)).toEqual([["cat"], ["ls"], ["echo", "done"]]);
    expect(p.commands[0]?.stdin).toEqual(["npm i foo\n"]);
  });

  test("<<- strips leading tabs from the delimiter line", () => {
    const p = parseShell("bash <<-EOF\n\tnpm i a\n\tEOF\nls");
    expect(argvs(p)).toEqual([["bash"], ["ls"]]);
    expect(p.commands[0]?.stdin).toEqual(["\tnpm i a\n"]);
  });

  test("here-strings are attached as stdin", () => {
    const p = parseShell('bash <<< "npm i foo"');
    expect(p.commands[0]?.stdin).toEqual(["npm i foo"]);
  });
});

describe("parseShell: expansions and substitutions", () => {
  test.each([
    ["npm i $PKG", [["npm", "i", "<>"]]],
    ['npm i "${PKG}"', [["npm", "i", "<>"]]],
    ["npm i foo@$V", [["npm", "i", "<foo@>"]]],
    ["echo $1 $? $@", [["echo", "<>", "<>", "<>"]]],
    ["echo $(npm i foo)", [["npm", "i", "foo"], ["echo", "<>"]]],
    ['echo "x $(npm i "foo") y"', [["npm", "i", "foo"], ["echo", "<x  y>"]]],
    ["echo `npm i foo`", [["npm", "i", "foo"], ["echo", "<>"]]],
    ["echo $(echo $(pnpm add z))", [["pnpm", "add", "z"], ["echo", "<>"], ["echo", "<>"]]],
    ["echo $((1 + 2))", [["1", "+", "2"], ["echo", "<>"]]],
    ["diff <(npm i a) b", [["npm", "i", "a"], ["diff", "<>", "b"]]],
    ["$(which npm) install foo", [["which", "npm"], ["<>", "install", "foo"]]],
  ])("%j", (input, expected) => {
    expect(parse(input)).toEqual(expected);
  });

  test("nested commands are marked", () => {
    const p = parseShell("echo $(npm i foo)");
    expect(p.commands.map((c) => c.nested)).toEqual([true, false]);
  });
});

describe("parseShell: syntax errors", () => {
  test.each([
    "npm i 'foo",
    'npm i "foo',
    "npm i `foo",
    "echo $(npm i foo",
    "echo ${X",
    "npm i foo)",
    "(npm i foo",
    "npm i foo >",
    "npm i foo > ; ls",
  ])("%j", (input) => {
    expect(parseShell(input).error).toBeDefined();
  });

  test("nesting deeper than the limit is an error", () => {
    expect(parseShell("$(".repeat(20) + "npm i x" + ")".repeat(20)).error).toMatch(/deep/);
  });

  test("very long input is an error", () => {
    expect(parseShell("a".repeat(2 * 1024 * 1024)).error).toMatch(/long/);
  });
});
