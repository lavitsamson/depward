// Latency benchmark for the gate (Phase 2 Definition of done: warm p95 < 1.5 s, cold
// < 5 s). Hits the real npm registry: packuments, download counts, and tarballs are
// fetched and read in memory. Nothing is installed or run.
//
//   pnpm bench:gate [--runs 5] [--json]
//
// Each command is checked the way one `depward hook claude` call checks it: a fresh
// registry client (empty in-memory memo) over the disk cache.
//   cold: an empty disk cache per command, so every lookup and tarball goes to the network.
//   warm: the disk cache left by the cold run, `--runs` times per command.
// Times are `checkCommand` only. Process start and module import come on top (about
// 65 ms of imports; bare `node` start-up varies widely by machine).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { createDiskCache, createRegistryClient, defaultConfig } from "../packages/core/src/index.ts";
import { checkCommand, createPolicy } from "../packages/gate/src/index.ts";

/** Install commands an agent typically runs, from small to heavy. */
export const BENCH_COMMANDS: readonly string[] = [
  "npm install lodash",
  "npm i express",
  "pnpm add react react-dom",
  "npm install --save-dev typescript",
  "yarn add axios",
  "pnpm add -D vitest",
  "npm i zod",
  "npm install chalk commander",
  "bun add dayjs",
  "npm i -D eslint prettier",
  "pnpm add uuid nanoid",
  "npm install dotenv",
  "npx prettier --write .",
  "npm i ws",
  "pnpm add -D @types/node",
];

const { values } = parseArgs({
  options: { runs: { type: "string", default: "5" }, json: { type: "boolean", default: false } },
});
const runs = Number(values.runs);
if (!Number.isInteger(runs) || runs < 1) {
  console.error("usage: pnpm bench:gate [--runs N] [--json]");
  process.exit(2);
}

const config = defaultConfig();
const policy = createPolicy(config);

interface Sample {
  readonly command: string;
  readonly ms: number;
  readonly action: string;
  readonly errors: number;
}

async function timeOne(command: string, cacheDir: string): Promise<Sample> {
  // The same wiring as `depward hook claude`: one disk cache for registry data and analyses.
  const cache = createDiskCache(cacheDir);
  const registry = createRegistryClient({ cache });
  const start = performance.now();
  const decision = await checkCommand(command, { registry, config, policy, analysisCache: cache });
  const ms = performance.now() - start;
  const errors = decision.packages.reduce((n, p) => n + p.errors.length, 0);
  return { command, ms, action: decision.action, errors };
}

function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  const i = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, i)]!;
}

function summarize(samples: readonly Sample[]): { p50: number; p95: number; max: number; n: number } {
  const ms = samples.map((s) => s.ms).toSorted((a, b) => a - b);
  return { p50: percentile(ms, 50), p95: percentile(ms, 95), max: ms.at(-1) ?? Number.NaN, n: ms.length };
}

const f = (n: number): string => `${Math.round(n).toLocaleString("en-US")} ms`;

const root = await mkdtemp(join(tmpdir(), "depward-bench-"));
try {
  const cold: Sample[] = [];
  const warm: Sample[] = [];
  const shared = join(root, "shared");
  for (const [i, command] of BENCH_COMMANDS.entries()) {
    cold.push(await timeOne(command, join(root, `cold-${i}`)));
    await timeOne(command, shared); // fills the shared cache for the warm runs
  }
  for (let r = 0; r < runs; r++) {
    for (const command of BENCH_COMMANDS) warm.push(await timeOne(command, shared));
  }

  const result = { cold: summarize(cold), warm: summarize(warm), samples: { cold, warm } };
  if (values.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log("| Command | Cold | Warm p50 | Action |");
    console.log("|---|---:|---:|---|");
    for (const s of cold) {
      const w = summarize(warm.filter((x) => x.command === s.command));
      const note = s.errors > 0 ? ` (${s.errors} failed lookup${s.errors === 1 ? "" : "s"})` : "";
      console.log(`| \`${s.command}\` | ${f(s.ms)} | ${f(w.p50)} | ${s.action}${note} |`);
    }
    console.log();
    for (const [name, s] of [["cold", result.cold], ["warm", result.warm]] as const) {
      console.log(`${name}: n=${s.n} p50=${f(s.p50)} p95=${f(s.p95)} max=${f(s.max)}`);
    }
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
