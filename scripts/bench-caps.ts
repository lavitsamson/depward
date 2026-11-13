// Runtime-layer overhead (Phase 4 DoD: under 5% on a request benchmark). Usage:
//   pnpm bench:caps [rounds]        (default 5)
// Runs the Express + Prisma-like fixture server (packages/caps/test/fixtures/app) with
// and without `--import @depward/caps/register` (from source), alternating inside each
// round so machine-load drift hits both equally. Reports medians. No network beyond
// 127.0.0.1; child processes run without a shell.

import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const APP = fileURLToPath(new URL("../packages/caps/test/fixtures/app/", import.meta.url));
const REGISTER = pathToFileURL(fileURLToPath(new URL("../packages/caps/src/runtime/register.ts", import.meta.url))).href;
const ROUNDS = Number(process.argv[2] ?? 5);
const out = mkdtempSync(join(tmpdir(), "depward-bench-caps-"));
const MODES: Record<string, string[]> = { baseline: [], observe: ["--import", REGISTER] };
const env = { ...process.env, DEPWARD_CAPS_OUT: join(out, "observed.json"), DEPWARD_CAPS_MODE: "", DEPWARD_CAPS_ENV: "" };
const median = (xs: number[]): number => xs.toSorted((a, b) => a - b)[Math.floor(xs.length / 2)] ?? Number.NaN;

function startup(mode: string): number {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, [...(MODES[mode] ?? []), join(APP, "server.mjs"), "1"], { env });
  if (r.status !== 0) throw new Error(`startup ${mode} failed: ${String(r.stderr)}`);
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

async function requests(mode: string, total = 6000, concurrency = 16): Promise<number> {
  const child = spawn(process.execPath, [...(MODES[mode] ?? []), join(APP, "server.mjs")], { env, stdio: ["ignore", "pipe", "inherit"] });
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
    await Promise.all(Array.from({ length: concurrency }, async () => {
      while (next < n) await one(next++);
    }));
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

const startupMs: Record<string, number[]> = { baseline: [], observe: [] };
const reqPerSec: Record<string, number[]> = { baseline: [], observe: [] };
for (let round = 0; round < ROUNDS; round++) {
  const order = round % 2 === 0 ? ["baseline", "observe"] : ["observe", "baseline"];
  for (const mode of order) {
    for (let i = 0; i < 3; i++) startupMs[mode]?.push(startup(mode));
    reqPerSec[mode]?.push(await requests(mode));
  }
  process.stderr.write(`round ${round + 1}/${ROUNDS} done\n`);
}
rmSync(out, { recursive: true, force: true });

const base = median(reqPerSec["baseline"] ?? []);
const obs = median(reqPerSec["observe"] ?? []);
process.stdout.write(
  `${JSON.stringify(
    {
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
      rounds: ROUNDS,
      startupMs: { baseline: Math.round(median(startupMs["baseline"] ?? [])), observe: Math.round(median(startupMs["observe"] ?? [])) },
      reqPerSec: { baseline: Math.round(base), observe: Math.round(obs) },
      requestOverheadPct: Math.round(((base - obs) / base) * 1000) / 10,
    },
    null,
    2,
  )}\n`,
);
