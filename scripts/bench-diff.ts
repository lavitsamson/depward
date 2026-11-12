// Noise benchmark for the behavioral diff (Phase 3 Definition of done: 50 real patch or
// minor updates of popular packages produce no `high` findings, or each one is reviewed
// and justified). Hits the real npm registry: packuments and tarballs are fetched and
// read in memory. Nothing is installed or run.
//
//   pnpm bench:diff [--count 50] [--concurrency 4] [--out results.json]
//
// Packages come from data/popular-packages.json, most downloaded first. For each one the
// update is `latest` against the highest earlier stable version with the same major (so a
// patch or minor update). Packages whose latest is a prerelease or a new major are
// skipped. The summary counts risks and lists every finding of `high` or above.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { createDiskCache, createRegistryClient, defaultCacheDir, isPrerelease, type Packument, type RegistryClient } from "../packages/core/src/index.ts";
import { compareVersions, diffVersions, mapLimit, type PackageChangeResult } from "../packages/diff/src/index.ts";

const { values } = parseArgs({
  options: {
    count: { type: "string", default: "50" },
    concurrency: { type: "string", default: "4" },
    out: { type: "string" },
  },
});
const count = Number(values.count);
const concurrency = Number(values.concurrency);
if (!Number.isInteger(count) || count < 1 || !Number.isInteger(concurrency) || concurrency < 1) {
  console.error("usage: pnpm bench:diff [--count N] [--concurrency N] [--out file.json]");
  process.exit(2);
}

const data = JSON.parse(await readFile(join(import.meta.dirname, "..", "data", "popular-packages.json"), "utf8")) as {
  packages: { name: string; weeklyDownloads: number }[];
};
const names = data.packages.toSorted((a, b) => b.weeklyDownloads - a.weeklyDownloads).map((p) => p.name);

const cache = createDiskCache(defaultCacheDir(process.env));
const registry: RegistryClient = createRegistryClient({ timeoutMs: 60_000, cache });

const major = (v: string): string => v.split(".")[0] ?? "";

/** `[from, to]` for the latest patch or minor update, or `null`. */
function pickUpdate(doc: Packument): [string, string] | null {
  const latest = doc["dist-tags"]["latest"];
  if (latest === undefined || isPrerelease(latest) || !Object.hasOwn(doc.versions, latest)) return null;
  const earlier = Object.keys(doc.versions)
    .filter((v) => !isPrerelease(v) && major(v) === major(latest) && compareVersions(v, latest) < 0)
    .toSorted(compareVersions);
  const from = earlier.at(-1);
  return from === undefined ? null : [from, latest];
}

// Choose updates in popularity order until there are enough.
const updates: { name: string; from: string; to: string }[] = [];
for (const name of names) {
  if (updates.length >= count) break;
  const doc = await registry.packument(name).catch(() => null);
  const pair = doc ? pickUpdate(doc) : null;
  if (pair) updates.push({ name, from: pair[0], to: pair[1] });
}

const started = performance.now();
let done = 0;
const results: PackageChangeResult[] = await mapLimit(updates, concurrency, async (u) => {
  const r = await diffVersions(u.name, u.from, u.to, { registry, analysisCache: cache });
  done++;
  process.stderr.write(`\r${done}/${updates.length} ${u.name}`.padEnd(60));
  return r;
});
process.stderr.write("\n");

const byRisk: Record<string, number> = {};
for (const r of results) byRisk[r.risk] = (byRisk[r.risk] ?? 0) + 1;
const byId: Record<string, Record<string, number>> = {};
for (const f of results.flatMap((r) => r.findings)) {
  byId[f.id] ??= {};
  const counts = byId[f.id] as Record<string, number>;
  counts[f.severity] = (counts[f.severity] ?? 0) + 1;
}

console.log(`${results.length} updates in ${Math.round((performance.now() - started) / 1000)} s`);
console.log("risk:", byRisk);
console.log("findings by id and severity:", byId);
console.log("\nhigh or above:");
for (const r of results) {
  const serious = r.findings.filter((f) => f.severity === "high" || f.severity === "critical");
  if (serious.length === 0 && r.errors.length === 0) continue;
  console.log(`  ${r.risk.padEnd(8)} ${r.name} ${r.from} → ${r.to}`);
  for (const f of serious) console.log(`      ${f.severity} ${f.id}: ${f.message}`);
  for (const e of r.errors) console.log(`      error ${e.code}: ${e.message}`);
}

if (values.out) {
  const slim = results.map((r) => ({ name: r.name, from: r.from, to: r.to, risk: r.risk, findings: r.findings.map((f) => ({ id: f.id, severity: f.severity, message: f.message, evidence: f.evidence.slice(0, 3) })), errors: r.errors.map((e) => `${e.code}: ${e.message}`) }));
  await writeFile(values.out, `${JSON.stringify(slim, null, 2)}\n`);
}
