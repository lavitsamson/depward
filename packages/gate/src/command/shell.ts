// A small POSIX-ish shell lexer. It splits a command line into simple commands (argv
// word lists) and never evaluates anything: variables and substitutions are not
// expanded. Words that would be computed at run time are marked `dynamic`. Commands
// inside `$(…)`, backticks, and `<(…)` are lexed too and listed with `nested: true`,
// because the shell runs them.

import { DepwardError } from "@depward/core";

/** One shell word after quote removal. */
export interface Word {
  /** The literal text. Expansions contribute nothing to it. */
  readonly text: string;
  /** True if part of the word comes from `$VAR`, `${…}`, `$(…)`, or backticks. */
  readonly dynamic: boolean;
}

/** A simple command: the words between two control operators. */
export interface SimpleCommand {
  readonly words: readonly Word[];
  /** The command's source text, from its first word to its end (heredoc bodies excluded). */
  readonly text: string;
  /** Heredoc bodies and here-strings fed to this command's stdin. */
  readonly stdin: readonly string[];
  /** True for commands found inside a command or process substitution. */
  readonly nested: boolean;
}

/** Result of {@link parseShell}. `error` is set when the input isn't valid shell syntax. */
export interface ShellParse {
  readonly commands: readonly SimpleCommand[];
  readonly error?: string;
}

/** Maximum nesting of substitutions and subshell recursion. */
export const MAX_SHELL_DEPTH: number = 8;
/** Inputs longer than this (in UTF-16 code units) are rejected. */
export const MAX_COMMAND_LENGTH: number = 1024 * 1024;

const NAME_START = /[A-Za-z_]/;
const NAME_CHAR = /[A-Za-z0-9_]/;
const SPECIAL_PARAM = /[0-9@*#?$!-]/;
const ANSI_C_ESCAPES: Record<string, string> = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", f: "\f", v: "\v" };

type Redirect = "discard" | "heredoc" | "heredoc-strip" | "herestring";

interface PendingHeredoc {
  readonly delimiter: string;
  readonly stripTabs: boolean;
  readonly stdin: string[];
}

function fail(message: string): never {
  throw new DepwardError("INVALID_ARGUMENT", message);
}

class Lexer {
  pos: number;
  private readonly src: string;
  private readonly depth: number;
  private readonly nested: boolean;
  private readonly out: SimpleCommand[];
  private words: Word[] = [];
  private stdin: string[] = [];
  private readonly heredocs: PendingHeredoc[] = [];
  private buf = "";
  private inWord = false;
  private dynamic = false;
  private plain = true;
  private redirect: Redirect | undefined;
  private parens = 0;
  private start = -1;

  constructor(src: string, start: number, depth: number, nested: boolean, out: SimpleCommand[]) {
    if (depth > MAX_SHELL_DEPTH) fail("command nesting is too deep");
    this.src = src;
    this.pos = start;
    this.depth = depth;
    this.nested = nested;
    this.out = out;
  }

  /** Lex to the end of input, or (with `closeParen`) to the `)` that closes a `$(`. */
  run(closeParen: boolean): number {
    const src = this.src;
    while (this.pos < src.length) {
      const c = src[this.pos] as string;
      const next = src[this.pos + 1];
      if (c === " " || c === "\t" || c === "\r") {
        this.endWord();
        this.pos++;
      } else if (c === "\n") {
        this.endCommand();
        this.pos++;
        this.readHeredocs();
      } else if (c === "#" && !this.inWord) {
        while (this.pos < src.length && src[this.pos] !== "\n") this.pos++;
      } else if (c === "\\") {
        if (next === "\n") this.pos += 2;
        else {
          this.append(next ?? "\\", false);
          this.pos += next === undefined ? 1 : 2;
        }
      } else if (c === "'") {
        const end = src.indexOf("'", this.pos + 1);
        if (end < 0) fail("unterminated single quote");
        this.append(src.slice(this.pos + 1, end), false);
        this.pos = end + 1;
      } else if (c === '"') {
        this.readDoubleQuoted();
      } else if (c === "`") {
        this.readBackticks();
      } else if (c === "$") {
        this.readDollar(false);
      } else if (c === "&" && next === ">") {
        this.endWord();
        this.pos += src[this.pos + 2] === ">" ? 3 : 2;
        this.redirect = "discard";
      } else if (c === ";" || c === "&" || c === "|") {
        this.endCommand();
        this.pos += next === c || (c === "|" && next === "&") ? 2 : 1;
      } else if (c === "(") {
        this.endCommand();
        this.parens++;
        this.pos++;
      } else if (c === ")") {
        this.endCommand();
        this.pos++;
        if (this.parens === 0) {
          if (closeParen) return this.pos;
          fail("unbalanced )");
        }
        this.parens--;
      } else if (c === "<" || c === ">") {
        this.readRedirect(c);
      } else {
        this.append(c, true);
        this.pos++;
      }
    }
    this.endCommand();
    if (closeParen) fail("unterminated $(");
    if (this.parens > 0) fail("unbalanced (");
    return this.pos;
  }

  private beginWord(): void {
    if (!this.inWord && this.words.length === 0 && this.start < 0) this.start = this.pos;
  }

  private append(text: string, plain: boolean): void {
    this.beginWord();
    this.buf += text;
    this.inWord = true;
    if (!plain) this.plain = false;
  }

  private markDynamic(): void {
    this.beginWord();
    this.inWord = true;
    this.dynamic = true;
    this.plain = false;
  }

  private endWord(): void {
    if (!this.inWord) return;
    const word: Word = { text: this.buf, dynamic: this.dynamic };
    this.buf = "";
    this.inWord = false;
    this.dynamic = false;
    this.plain = true;
    const redirect = this.redirect;
    this.redirect = undefined;
    if (redirect === undefined) this.words.push(word);
    else if (redirect === "herestring") this.stdin.push(word.text);
    else if (redirect !== "discard") {
      this.heredocs.push({ delimiter: word.text, stripTabs: redirect === "heredoc-strip", stdin: this.stdin });
    }
  }

  private endCommand(): void {
    this.endWord();
    if (this.redirect !== undefined) fail("missing redirection target");
    if (this.words.length > 0) {
      const text = this.src.slice(this.start, this.pos).trim();
      this.out.push({ words: this.words, text, stdin: this.stdin, nested: this.nested });
    }
    this.start = -1;
    this.words = [];
    this.stdin = [];
  }

  private readHeredocs(): void {
    const src = this.src;
    for (const doc of this.heredocs.splice(0)) {
      let body = "";
      while (this.pos < src.length) {
        const nl = src.indexOf("\n", this.pos);
        const end = nl < 0 ? src.length : nl;
        const line = src.slice(this.pos, end);
        this.pos = end + 1;
        const bare = (doc.stripTabs ? line.replace(/^\t+/, "") : line).replace(/\r$/, "");
        if (bare === doc.delimiter) break;
        body += line + "\n";
      }
      doc.stdin.push(body);
    }
  }

  private readRedirect(c: "<" | ">"): void {
    // A digits-only unquoted word right before the operator is a file descriptor.
    if (this.inWord && this.plain && /^\d+$/.test(this.buf)) {
      this.buf = "";
      this.inWord = false;
    } else this.endWord();
    const src = this.src;
    if (src[this.pos + 1] === "(") {
      // Process substitution, <(…) or >(…): its commands run; the word is dynamic.
      this.beginWord();
      this.pos = this.substitute(this.pos + 2);
      this.markDynamic();
      return;
    }
    this.pos++;
    let kind: Redirect = "discard";
    if (c === "<" && src[this.pos] === "<") {
      this.pos++;
      if (src[this.pos] === "<") {
        this.pos++;
        kind = "herestring";
      } else if (src[this.pos] === "-") {
        this.pos++;
        kind = "heredoc-strip";
      } else kind = "heredoc";
    } else if (src[this.pos] === ">" || src[this.pos] === "&" || src[this.pos] === "|") {
      this.pos++;
    }
    this.redirect = kind;
  }

  private readDoubleQuoted(): void {
    const src = this.src;
    this.beginWord();
    this.pos++;
    this.append("", false);
    for (;;) {
      if (this.pos >= src.length) fail("unterminated double quote");
      const c = src[this.pos] as string;
      if (c === '"') {
        this.pos++;
        return;
      }
      if (c === "\\") {
        const next = src[this.pos + 1];
        if (next === "\n") this.pos += 2;
        else if (next !== undefined && '$`"\\'.includes(next)) {
          this.append(next, false);
          this.pos += 2;
        } else {
          this.append("\\", false);
          this.pos++;
        }
      } else if (c === "$") this.readDollar(true);
      else if (c === "`") this.readBackticks();
      else {
        this.append(c, false);
        this.pos++;
      }
    }
  }

  private readDollar(inDoubleQuotes: boolean): void {
    this.beginWord();
    const src = this.src;
    const next = src[this.pos + 1];
    if (next === "(") {
      this.pos = this.substitute(this.pos + 2);
      this.markDynamic();
    } else if (next === "{") {
      let depth = 0;
      let i = this.pos + 1;
      for (; i < src.length; i++) {
        if (src[i] === "{") depth++;
        else if (src[i] === "}" && --depth === 0) break;
      }
      if (i >= src.length) fail("unterminated ${");
      this.pos = i + 1;
      this.markDynamic();
    } else if (!inDoubleQuotes && next === "'") {
      this.readAnsiC();
    } else if (!inDoubleQuotes && next === '"') {
      this.pos++;
      this.readDoubleQuoted();
    } else if (next !== undefined && NAME_START.test(next)) {
      this.pos += 2;
      while (this.pos < src.length && NAME_CHAR.test(src[this.pos] as string)) this.pos++;
      this.markDynamic();
    } else if (next !== undefined && SPECIAL_PARAM.test(next)) {
      this.pos += 2;
      this.markDynamic();
    } else {
      this.append("$", false);
      this.pos++;
    }
  }

  /** `$'…'`: ANSI-C quoting with backslash escapes. */
  private readAnsiC(): void {
    const src = this.src;
    let i = this.pos + 2;
    let text = "";
    for (;;) {
      if (i >= src.length) fail("unterminated $' quote");
      const c = src[i] as string;
      if (c === "'") break;
      if (c === "\\" && i + 1 < src.length) {
        const e = src[i + 1] as string;
        text += ANSI_C_ESCAPES[e] ?? e;
        i += 2;
      } else {
        text += c;
        i++;
      }
    }
    this.pos = i + 1;
    this.append(text, false);
  }

  private readBackticks(): void {
    this.beginWord();
    const src = this.src;
    let i = this.pos + 1;
    let body = "";
    for (;;) {
      if (i >= src.length) fail("unterminated backtick");
      const c = src[i] as string;
      if (c === "`") break;
      if (c === "\\" && i + 1 < src.length && "`$\\".includes(src[i + 1] as string)) {
        body += src[i + 1];
        i += 2;
      } else {
        body += c;
        i++;
      }
    }
    this.pos = i + 1;
    new Lexer(body, 0, this.depth + 1, true, this.out).run(false);
    this.markDynamic();
  }

  /** Lex a `$(` or `<(` body that starts at `start`; returns the index after its `)`. */
  private substitute(start: number): number {
    return new Lexer(this.src, start, this.depth + 1, true, this.out).run(true);
  }
}

/**
 * Split a shell command line into simple commands, without evaluating anything.
 *
 * Handles quotes, backslash escapes, `&&`, `||`, `;`, `|`, `&`, newlines, subshell
 * parentheses, redirections (including heredocs, whose bodies become `stdin`), and
 * comments. On a syntax error, `commands` holds whatever was lexed before it.
 *
 * @param depth - Nesting depth of the caller, for recursive parsing of `sh -c` strings.
 */
export function parseShell(input: string, depth = 0): ShellParse {
  const commands: SimpleCommand[] = [];
  if (input.length > MAX_COMMAND_LENGTH) return { commands, error: "command is too long" };
  try {
    new Lexer(input, 0, depth, depth > 0, commands).run(false);
    return { commands };
  } catch (error) {
    if (error instanceof DepwardError) return { commands, error: error.message };
    throw error;
  }
}
