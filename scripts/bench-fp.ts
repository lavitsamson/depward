// False-positive benchmark for the gate (Phase 2 Definition of done: on the top 1,000
// packages' latest versions, < 1% `deny` and < 5% `ask`). Hits the real npm registry:
// packuments, download counts, and tarballs are fetched and read in memory. Nothing is
// installed or run.
//
//   pnpm bench:fp [--top 1000] [--concurrency 8] [--out results.json]
//
// Every package is checked as `depward check <name>` with the default config. Names come
// from data/popular-packages.json (highest weekly downloads first). The summary counts
// decisions and, for every non-allow package, the finding IDs that caused it.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { createRegistryClient, defaultConfig, type RegistryClient } from "../packages/core/src/index.ts";
import { checkSpecs, createPolicy } from "../packages/gate/src/index.ts";

const { values } = parseArgs({
  options: {
    top: { type: "string", default: "1000" },
    concurrency: { type: "string", default: "8" },
    out: { type: "string" },
  },
});
const top = Number(values.top);
const concurrency = Number(values.concurrency);
if (!Number.isInteger(top) || top < 1 || !Number.isInteger(concurrency) || concurrency < 1) {
  console.error("usage: pnpm bench:fp [--top N] [--concurrency N] [--out file.json]");
  process.exit(2);
}

const data = JSON.parse(await readFile(join(import.meta.dirname, "..", "data", "popular-packages.json"), "utf8")) as {
  snapshot: string;
  packages: { name: string; weeklyDownloads: number }[];
};
const names = data.packages
  .toSorted((a, b) => b.weeklyDownloads - a.weeklyDownloads)
  .slice(0, top)
  .map((p) => p.name);

const config = defaultConfig();
const policy = createPolicy(config);
// The disk cache (default location) makes re-runs cheap; the result doesn't depend on it.
const client = createRegistryClient({ timeoutMs: 60_000 });

// api.npmjs.org answers a 1,000-package burst with HTTP 429. One agent command checks a
// few packages, so only the benchmark needs this: retry 429s with backoff, so a rate
// limit isn't counted as a lookup error.
async function retry429<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= 8 || !/HTTP 429/.test(String((err as Error).message))) throw err;
      await new Promise((r) => setTimeout(r, Math.min(60_000, 2000 * 2 ** attempt) * (0.5 + Math.random())));
    }
  }
}
const registry: RegistryClient = {
  packument: (name) => retry429(() => client.packument(name)),
  versionMeta: (name, version) => retry429(() => client.versionMeta(name, version)),
  weeklyDownloads: (name) => retry429(() => client.weeklyDownloads(name)),
  attestations: (name, version) => retry429(() => client.attestations(name, version)),
  tarball: (meta) => retry429(() => client.tarball(meta)),
};

export interface FpResult {
  readonly name: string;
  readonly version: string | null;
  readonly action: string;
  /** IDs of the findings whose action equals the package's (the causes). */
  readonly causes: string[];
  readonly errors: string[];
  readonly ms: number;
}

const results: FpResult[] = [];
let next = 0;
let done = 0;
const started = performance.now();
async function worker(): Promise<void> {
  while (next < names.length) {
    const i = next++;
    const name = names[i]!;
    const t = performance.now();
    try {
      const d = await checkSpecs([name], { registry, config, policy });
      const p = d.packages[0]!;
      const causes = p.action === "allow" ? [] : p.findings.filter((f) => f.action === p.action).map((f) => f.finding.id);
      if (p.action !== "allow" && p.errorAction === p.action && p.errors.length > 0) causes.push("lookup-error");
      results[i] = { name, version: p.version, action: p.action, causes: [...new Set(causes)].toSorted(), errors: p.errors.map((e) => `${e.code}: ${e.message}`), ms: Math.round(performance.now() - t) };
    } catch (err) {
      results[i] = { name, version: null, action: "error", causes: [], errors: [String((err as Error).message)], ms: Math.round(performance.now() - t) };
    }
    done++;
    if (done % 50 === 0) process.stderr.write(`${done}/${names.length} (${Math.round((performance.now() - started) / 1000)} s)\n`);
  }
}
await Promise.all(Array.from({ length: concurrency }, worker));

const count = (a: string): number => results.filter((r) => r.action === a).length;
const pct = (n: number): string => `${((100 * n) / results.length).toFixed(1)}%`;
const byCause = new Map<string, string[]>();
for (const r of results) for (const c of r.causes) byCause.set(`${r.action} ${c}`, [...(byCause.get(`${r.action} ${c}`) ?? []), r.name]);

console.log(`Top ${results.length} packages (popular-packages snapshot ${data.snapshot}), default config, ${new Date().toISOString().slice(0, 10)}`);
for (const a of ["allow", "ask", "deny", "error"]) console.log(`${a}: ${count(a)} (${pct(count(a))})`);
// The Phase 2 target counts false positives. A cooldown ask (`version-too-new` alone) is
// the policy working as intended: the version really is new. It is reported separately.
const cooldownOnly = results.filter((r) => r.action === "ask" && r.causes.length === 1 && r.causes[0] === "version-too-new").length;
console.log(`ask excluding cooldown-only: ${count("ask") - cooldownOnly} (${pct(count("ask") - cooldownOnly)}); cooldown-only: ${cooldownOnly} (${pct(cooldownOnly)})`);
console.log(`total ${Math.round((performance.now() - started) / 1000)} s\n`);
console.log("| Action | Cause | Packages | Examples |");
console.log("|---|---|---:|---|");
for (const [key, list] of [...byCause].toSorted((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))) {
  const [action, cause] = key.split(" ");
  console.log(`| ${action} | \`${cause}\` | ${list.length} | ${list.slice(0, 6).join(", ")}${list.length > 6 ? ", …" : ""} |`);
}
const errored = results.filter((r) => r.action === "error");
if (errored.length > 0) console.log(`\nerrors: ${errored.map((r) => `${r.name} (${r.errors[0]})`).join(", ")}`);
if (values.out) await writeFile(values.out, `${JSON.stringify(results, null, 2)}\n`);
