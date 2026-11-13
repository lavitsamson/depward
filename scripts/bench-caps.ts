// Runtime-layer overhead, observe and enforce (Phase 4 DoD: under 5% on a request
// benchmark). Usage:
//   pnpm bench:caps [rounds]        (default 5)
// Runs the Express + Prisma-like fixture server (packages/caps/test/fixtures/app) without
// the runtime layer, in observe mode, and in enforce mode (register from source). Modes
// rotate inside each round so machine-load drift hits each one equally. Reports medians.
// No network beyond 127.0.0.1; child processes run without a shell.

import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const APP = fileURLToPath(new URL("../packages/caps/test/fixtures/app/", import.meta.url));
const REGISTER = pathToFileURL(fileURLToPath(new URL("../packages/caps/src/runtime/register.ts", import.meta.url))).href;
const ROUNDS = Number(process.argv[2] ?? 5);
const out = mkdtempSync(join(tmpdir(), "depward-bench-caps-"));
const MODES: Record<string, string[]> = { baseline: [], observe: ["--import", REGISTER], enforce: ["--import", REGISTER] };

// Enforce with every capability the fixture uses approved, so the run measures the cost
// of checking, not of failing.
const lockfile = join(out, "capabilities.lock.json");
writeFileSync(
  lockfile,
  JSON.stringify({
    version: 1,
    packages: {
      "orm-client@1.0.0": { capabilities: ["crypto", "env", "fs"] },
      "web-framework@1.0.0": { capabilities: ["fs", "net"] },
      "etag-lite@1.0.0": { capabilities: ["crypto"] },
    },
  }),
);
const shared = { ...process.env, DEPWARD_CAPS_OUT: join(out, "observed.json"), DEPWARD_CAPS_ENV: "", DEPWARD_CAPS_LOCKFILE: lockfile };
const envFor = (mode: string): NodeJS.ProcessEnv => ({ ...shared, DEPWARD_CAPS_MODE: mode === "enforce" ? "enforce" : "" });
const median = (xs: number[]): number => xs.toSorted((a, b) => a - b)[Math.floor(xs.length / 2)] ?? Number.NaN;

function startup(mode: string): number {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, [...(MODES[mode] ?? []), join(APP, "server.mjs"), "1"], { env: envFor(mode) });
  if (r.status !== 0) throw new Error(`startup ${mode} failed: ${String(r.stderr)}`);
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

async function requests(mode: string, total = 6000, concurrency = 16): Promise<number> {
  const child = spawn(process.execPath, [...(MODES[mode] ?? []), join(APP, "server.mjs")], { env: envFor(mode), stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise<number>((resolve) => child.stdout.once("data", (d) => resolve(Number(String(d).trim()))));
  const agent = new http.Agent({ keepAlive: true, maxSockets: concurrency });
  const paths = ["/users", "/", "/health"];
  const one = (i: number): Promise<void> =>
    new Promise((resolve, reject) => {
      http.get({ host: "127.0.0.1", port, path: paths[i % 3], agent }, (res) => {
        res.resume();
        res.on("end", () => (res.statusCode === 200 ? resolve() : reject(new Error(String(res.statusCode)))));
      }).on("error", reject);
    });
  const drive = async (n: number): Promise<void> => {
    let next = 0;
    await Promise.all(
      Array.from({ length: concurrency }, async () => {
        while (next < n) await one(next++);
      }),
    );
  };
  await drive(1000); // warm-up
  const t0 = process.hrtime.bigint();
  await drive(total);
  const secs = Number(process.hrtime.bigint() - t0) / 1e9;
  agent.destroy();
  child.kill();
  await new Promise((resolve) => child.once("exit", resolve));
  return total / secs;
}

const names = Object.keys(MODES);
const startupMs: Record<string, number[]> = Object.fromEntries(names.map((m) => [m, []]));
const reqPerSec: Record<string, number[]> = Object.fromEntries(names.map((m) => [m, []]));
for (let round = 0; round < ROUNDS; round++) {
  const order = names.map((_, i) => names[(i + round) % names.length] as string);
  for (const mode of order) {
    for (let i = 0; i < 3; i++) startupMs[mode]?.push(startup(mode));
    reqPerSec[mode]?.push(await requests(mode));
  }
  process.stderr.write(`round ${round + 1}/${ROUNDS} done\n`);
}
rmSync(out, { recursive: true, force: true });

const baseRps = median(reqPerSec["baseline"] ?? []);
const pct = (m: string): number => Math.round(((baseRps - median(reqPerSec[m] ?? [])) / baseRps) * 1000) / 10;
const summary = {
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  rounds: ROUNDS,
  startupMs: Object.fromEntries(names.map((m) => [m, Math.round(median(startupMs[m] ?? []))])),
  reqPerSec: Object.fromEntries(names.map((m) => [m, Math.round(median(reqPerSec[m] ?? []))])),
  requestOverheadPct: { observe: pct("observe"), enforce: pct("enforce") },
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
