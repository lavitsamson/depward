// Entry point of the bundled Action (action/dist/index.mjs). Wires runAction to the
// runner: process.env, stdout, global fetch, and the working directory (the checkout).

import { DEFAULT_CONCURRENCY, VERSION } from "@depward/diff";
import { computeDiff } from "../../packages/cli/src/diff.ts";
import { createLog } from "./env.ts";
import { createGitHub } from "./github.ts";
import { reportError, runAction } from "./run.ts";

const env = process.env;
const log = createLog((line) => process.stdout.write(`${line}\n`));
const rt = {
  version: VERSION,
  env,
  cwd: process.cwd(),
  now: () => performance.now(),
  stdout: (s: string) => process.stdout.write(s),
  stderr: (s: string) => process.stderr.write(s),
};

try {
  process.exitCode = await runAction({
    env,
    log,
    version: VERSION,
    computeView: async (base) =>
      (
        await computeDiff(
          { lockfile: true, positionals: [], base, head: undefined, concurrency: DEFAULT_CONCURRENCY, config: undefined, offline: false },
          rt,
        )
      ).view,
    github: (token) =>
      createGitHub({ token, repository: env["GITHUB_REPOSITORY"] ?? "", ...(env["GITHUB_API_URL"] ? { apiUrl: env["GITHUB_API_URL"] } : {}) }),
  });
} catch (err) {
  process.exitCode = reportError(log, err);
}
