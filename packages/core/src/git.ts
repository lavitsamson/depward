// Reads files from git history without a shell. `git` is run with execFile and fixed
// arguments; the ref is validated first so it cannot be read as an option.
// https://git-scm.com/docs/git-rev-parse, https://git-scm.com/docs/git-cat-file

import { execFile } from "node:child_process";
import { DepwardError } from "./errors.ts";

/** Options for {@link readFileAtRef}. */
export interface ReadFileAtRefOptions {
  /** Default 100 MB. */
  maxBytes?: number;
  /** Default 30 s. */
  timeoutMs?: number;
}

interface GitResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}

function git(args: string[], cwd: string, opts: Required<ReadFileAtRefOptions>): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      args,
      {
        cwd,
        encoding: "utf8",
        maxBuffer: opts.maxBytes,
        timeout: opts.timeoutMs,
        windowsHide: true,
        // Never prompt for credentials and never take repository locks.
        env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" },
      },
      (err, stdout, stderr) => {
        if (!err) return resolve({ ok: true, stdout, stderr });
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ENOENT") return reject(new DepwardError("GIT", "git is not installed or not on PATH", { cause: err }));
        if (code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
          return reject(new DepwardError("LIMIT_EXCEEDED", "file at ref is larger than the size limit", { cause: err }));
        }
        if (err.killed) return reject(new DepwardError("TIMEOUT", "git timed out", { cause: err }));
        resolve({ ok: false, stdout, stderr });
      },
    );
  });
}

const SAFE_REF = /^[\w./~^@{}+-]+$/;

/**
 * Reads `path` (relative to `cwd`) as it was at git `ref`, like `git show <ref>:<path>`.
 * Returns `null` when the file does not exist at that ref.
 *
 * @throws DepwardError `INVALID_ARGUMENT` for a malformed ref, `GIT` when `cwd` is not a
 *   repository or the ref does not exist, `LIMIT_EXCEEDED`, `TIMEOUT`.
 */
export async function readFileAtRef(ref: string, path: string, cwd: string, opts: ReadFileAtRefOptions = {}): Promise<string | null> {
  const o = { maxBytes: opts.maxBytes ?? 100 * 1024 * 1024, timeoutMs: opts.timeoutMs ?? 30_000 };
  if (!SAFE_REF.test(ref) || ref.startsWith("-")) throw new DepwardError("INVALID_ARGUMENT", "invalid git ref");
  if (path.includes("\0") || path === "") throw new DepwardError("INVALID_ARGUMENT", "invalid path");

  const commit = await git(["rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`], cwd, o);
  if (!commit.ok) {
    const inRepo = await git(["rev-parse", "--git-dir"], cwd, o);
    throw new DepwardError("GIT", inRepo.ok ? "unknown git ref" : "not inside a git repository");
  }
  // `<commit>:./<path>` resolves relative to cwd rather than the repository root.
  const rel = `./${path.replaceAll("\\", "/").replace(/^\.\//, "")}`;
  const blob = await git(["cat-file", "blob", `${commit.stdout.trim()}:${rel}`], cwd, o);
  return blob.ok ? blob.stdout : null;
}
