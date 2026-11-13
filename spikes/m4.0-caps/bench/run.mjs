// Spike benchmark driver (spec question 5). Usage, from the repo root:
//   node spikes/m4.0-caps/bench/run.mjs [rounds]
// Modes alternate inside each round so machine-load drift hits every mode equally.
// Reports medians. Child processes run without a shell.
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const REGISTER = new URL("../register.mjs", import.meta.url).href;
const ROUNDS = Number(process.argv[2] ?? 5);
const MODES = {
  baseline: { args: [], env: {} },
  hooks: { args: ["--import", REGISTER], env: { DEPWARD_CAPS_GLOBALS: "0" } },
  "hooks+globals": { args: ["--import", REGISTER], env: {} },
};
const median = (xs) => xs.toSorted((a, b) => a - b)[Math.floor(xs.length / 2)];
const envFor = (mode) => ({ ...process.env, ...MODES[mode].env });

function startup(mode) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, [...MODES[mode].args, here("./startup.mjs")], { env: envFor(mode) });
  if (r.status !== 0) throw new Error(`startup ${mode} failed: ${r.stderr}`);
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

function percall(mode, extraEnv = {}) {
  const r = spawnSync(process.execPath, [...MODES[mode].args, here("./percall.mjs")], { env: { ...envFor(mode), ...extraEnv } });
  if (r.status !== 0) throw new Error(`percall ${mode} failed: ${r.stderr}`);
  return JSON.parse(r.stdout.toString());
}

async function requests(mode, total = 6000, concurrency = 16) {
  const child = spawn(process.execPath, [...MODES[mode].args, here("./server.mjs")], { env: envFor(mode), stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise((resolve) => child.stdout.once("data", (d) => resolve(Number(String(d).trim()))));
  const agent = new http.Agent({ keepAlive: true, maxSockets: concurrency });
  const paths = ["/users", "/", "/health"];
  const one = (i) =>
    new Promise((resolve, reject) => {
      http.get({ host: "127.0.0.1", port, path: paths[i % 3], agent }, (res) => {
        res.resume();
        res.on("end", () => (res.statusCode === 200 ? resolve() : reject(new Error(`${res.statusCode}`))));
      }).on("error", reject);
    });
  const drive = async (n) => {
    let next = 0;
    await Promise.all(Array.from({ length: concurrency }, async () => { while (next < n) await one(next++); }));
  };
  await drive(1000); // warm-up (JIT, file cache)
  const t0 = process.hrtime.bigint();
  await drive(total);
  const secs = Number(process.hrtime.bigint() - t0) / 1e9;
  agent.destroy();
  child.kill();
  return total / secs;
}

const modes = Object.keys(MODES);
const res = { startupMs: {}, reqPerSec: {}, perCallNs: {} };
for (const m of modes) { res.startupMs[m] = []; res.reqPerSec[m] = []; res.perCallNs[m] = []; }
res.perCallNs["hooks+globals(callsites)"] = [];

for (let round = 0; round < ROUNDS; round++) {
  const order = modes.map((_, i) => modes[(i + round) % modes.length]);
  for (const m of order) {
    for (let i = 0; i < 3; i++) res.startupMs[m].push(startup(m));
    res.reqPerSec[m].push(await requests(m));
    res.perCallNs[m].push(percall(m));
  }
  res.perCallNs["hooks+globals(callsites)"].push(percall("hooks+globals", { DEPWARD_CAPS_STACK: "callsites" }));
  process.stderr.write(`round ${round + 1}/${ROUNDS} done\n`);
}

const summary = { node: process.version, platform: `${process.platform}-${process.arch}`, rounds: ROUNDS, startupMs: {}, reqPerSec: {}, perCallNs: {} };
for (const m of modes) {
  summary.startupMs[m] = Math.round(median(res.startupMs[m]));
  summary.reqPerSec[m] = Math.round(median(res.reqPerSec[m]));
}
for (const [m, rows] of Object.entries(res.perCallNs)) {
  summary.perCallNs[m] = Object.fromEntries(Object.keys(rows[0]).map((k) => [k, Math.round(median(rows.map((r) => r[k])) * 10) / 10]));
}
const base = summary.reqPerSec.baseline;
summary.requestOverheadPct = Object.fromEntries(modes.map((m) => [m, Math.round(((base - summary.reqPerSec[m]) / base) * 1000) / 10]));
process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
