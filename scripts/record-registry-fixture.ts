// Records a real public packument (and its weekly download count) as an offline fixture.
//
//   node scripts/record-registry-fixture.ts <name> [--keep 5]
//
// The packument is trimmed to the newest `--keep` versions (plus every dist-tag target),
// and `readme` fields are dropped, so fixtures stay small. Only metadata is fetched;
// no tarball is downloaded and no package code is run.

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: { keep: { type: "string", default: "5" } },
});
const name = positionals[0];
if (!name || !/^(?:@[\w.~-]+\/)?[\w.~-]+$/.test(name)) {
  console.error("usage: node scripts/record-registry-fixture.ts <package-name> [--keep N]");
  process.exit(2);
}
const keep = Number(values.keep);
const root = join(import.meta.dirname, "..", "fixtures", "registry");
const stem = name.replace("/", "+");

async function getJson(url: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return (await res.json()) as Record<string, unknown>;
}

const doc = await getJson(`https://registry.npmjs.org/${name.replace("/", "%2f")}`);
const versions = doc["versions"] as Record<string, Record<string, unknown>>;
const time = doc["time"] as Record<string, string>;
const tags = doc["dist-tags"] as Record<string, string>;
const newest = Object.keys(versions)
  .toSorted((a, b) => (time[b] ?? "").localeCompare(time[a] ?? ""))
  .slice(0, keep);
const kept = new Set([...newest, ...Object.values(tags)]);

delete doc["readme"];
doc["versions"] = Object.fromEntries(
  [...kept].filter((v) => versions[v]).map((v) => {
    const { readme: _readme, ...meta } = versions[v]!;
    return [v, meta];
  }),
);
doc["time"] = Object.fromEntries(Object.entries(time).filter(([k]) => k === "created" || k === "modified" || kept.has(k)));

await mkdir(join(root, "packuments"), { recursive: true });
await mkdir(join(root, "downloads"), { recursive: true });
await writeFile(join(root, "packuments", `${stem}.json`), `${JSON.stringify(doc, null, 2)}\n`);
const downloads = await getJson(`https://api.npmjs.org/downloads/point/last-week/${name}`);
await writeFile(join(root, "downloads", `${stem}.json`), `${JSON.stringify(downloads, null, 2)}\n`);
console.log(`recorded ${name}: ${kept.size} versions`);
