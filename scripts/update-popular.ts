// Regenerates data/popular-packages.json: the most-downloaded npm packages with their
// weekly download counts. The typosquat check compares requested names against it.
//
//   node scripts/update-popular.ts [--limit 10000] [--out data/popular-packages.json]
//                                  [--range YYYY-MM-DD:YYYY-MM-DD] [--gap-ms 2000]
//
// Be a polite client: every request (both APIs, retries included) goes through one
// pacer. It is strictly sequential, waits at least --gap-ms plus random jitter between
// requests, doubles the gap after each 429 (up to 30 s) and only slowly eases back. npm
// rate-limits the download API hard (429 after about 20 quick requests), so a full run
// takes a few hours. That is fine for a file refreshed about monthly.
// Progress is checkpointed per range to a file in the OS temp dir. Rerunning resumes:
// on the same UTC day automatically, or later by passing the same --range.
//
// Data source (ADR 0003):
// 1. Candidate names: ecosyste.ms, which ranks npm packages by last-month downloads.
//    https://packages.ecosyste.ms/docs (GET /api/v1/registries/npmjs.org/packages,
//    sort=downloads, per_page at most 1000). Data license: CC BY-SA 4.0.
// 2. Counts: npm's own download-counts API, point totals for the last 7 full days.
//    https://github.com/npm/registry/blob/main/docs/download-counts.md
//    Bulk queries take at most 128 packages and no scoped names, so scoped packages are
//    fetched one at a time.
//
// Only metadata is fetched. No package code or tarball is downloaded.

import { readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    limit: { type: "string", default: "10000" },
    out: { type: "string", default: join(import.meta.dirname, "..", "data", "popular-packages.json") },
    "gap-ms": { type: "string", default: "2000" },
    range: { type: "string" },
  },
});
const limit = Number(values.limit);
const gapMs = Number(values["gap-ms"]);
if (
  !Number.isInteger(limit) ||
  limit < 1 ||
  !Number.isInteger(gapMs) ||
  gapMs < 0 ||
  (values.range !== undefined && !/^\d{4}-\d{2}-\d{2}:\d{4}-\d{2}-\d{2}$/.test(values.range))
) {
  console.error("usage: node scripts/update-popular.ts [--limit N] [--out path] [--range YYYY-MM-DD:YYYY-MM-DD] [--gap-ms N]");
  process.exit(2);
}

const ECOSYSTEMS = "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages";
// A fixed 7-day range, by default ending yesterday (UTC). `last-week` rolls over at
// midnight, which would mix two windows in one long run.
const DAY = 86_400_000;
const today = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate());
const RANGE =
  values.range ?? `${new Date(today - 7 * DAY).toISOString().slice(0, 10)}:${new Date(today - DAY).toISOString().slice(0, 10)}`;
const DOWNLOADS = `https://api.npmjs.org/downloads/point/${RANGE}`;
const USER_AGENT = "depward-update-popular (+https://github.com/lavitsamson/depward)";
const PAGE_SIZE = 1000;
const BULK_SIZE = 128;
// Fetch extra candidates: rankings by last month and by last week differ near the cutoff.
const OVERFETCH = 1.15;
const RATE_LIMIT_PAUSE_MS = 30_000;
const CHECKPOINT = join(tmpdir(), `depward-popular-${RANGE.replace(":", "_")}.json`);
const NAME_RE = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9_.~-][\w.~-]*$/i;

interface Point {
  downloads: number;
  start: string;
  end: string;
  package: string;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

const MAX_GAP_MS = 30_000;
let currentGap = gapMs;
let lastRequestAt = 0;

/** Waits until at least `currentGap` (plus up to 25% jitter) has passed since the last request. */
async function pace(): Promise<void> {
  const due = lastRequestAt + currentGap * (1 + Math.random() * 0.25);
  if (due > Date.now()) await sleep(due - Date.now());
  lastRequestAt = Date.now();
}

/** On 429: double the gap. On success: ease back 5% toward the base gap. */
function adjustGap(rateLimited: boolean): void {
  const next = rateLimited ? Math.min(Math.max(currentGap, 1000) * 2, MAX_GAP_MS) : Math.max(gapMs, currentGap * 0.95);
  if (rateLimited && next !== currentGap) console.error(`rate limited; slowing to one request per ${(next / 1000).toFixed(1)}s`);
  currentGap = next;
}

async function getJson(url: string): Promise<unknown> {
  for (let attempt = 1; ; attempt++) {
    let res: Response;
    try {
      await pace();
      res = await fetch(url, {
        headers: { accept: "application/json", "user-agent": USER_AGENT },
        signal: AbortSignal.timeout(120_000),
      });
      adjustGap(res.status === 429);
      if (res.ok) return await res.json();
    } catch (error) {
      // Network failures (ECONNRESET, timeouts, truncated bodies) are retried like a 5xx.
      if (attempt >= 10) throw error;
      const wait = 2 ** Math.min(attempt, 5) * 1000;
      console.error(`${String(error)} for ${url}; retrying in ${wait / 1000}s`);
      await sleep(wait);
      continue;
    }
    if (res.status === 404) return undefined;
    await res.body?.cancel();
    if ((res.status === 429 || res.status >= 500) && attempt < 10) {
      // Honor a real `retry-after` (seconds). npm sends `retry-after: 0`, so never wait less
      // than a pause long enough for its limit to reset.
      const retryAfter = Number(res.headers.get("retry-after")) * 1000;
      const floor = res.status === 429 ? RATE_LIMIT_PAUSE_MS * Math.min(attempt, 4) : 2 ** attempt * 1000;
      const wait = Number.isFinite(retryAfter) ? Math.max(floor, Math.min(retryAfter, 600_000)) : floor;
      console.error(`HTTP ${res.status} for ${url}; retrying in ${wait / 1000}s`);
      await sleep(wait);
      continue;
    }
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
}

function isPoint(value: unknown): value is Point {
  if (typeof value !== "object" || value === null) return false;
  const p = value as Record<string, unknown>;
  return Number.isSafeInteger(p["downloads"]) && typeof p["start"] === "string" && typeof p["end"] === "string" && typeof p["package"] === "string";
}

async function candidates(count: number): Promise<string[]> {
  const names = new Set<string>();
  for (let page = 1; names.size < count; page++) {
    const url = `${ECOSYSTEMS}?sort=downloads&order=desc&per_page=${PAGE_SIZE}&page=${page}`;
    const rows = await getJson(url);
    if (!Array.isArray(rows) || rows.length === 0) break;
    for (const row of rows as { name?: unknown }[]) {
      if (typeof row.name === "string" && NAME_RE.test(row.name) && row.name.length <= 214) names.add(row.name);
    }
    console.error(`candidates: ${names.size}`);
  }
  return [...names].slice(0, count);
}

async function loadCheckpoint(): Promise<Map<string, Point | null>> {
  try {
    const saved = JSON.parse(await readFile(CHECKPOINT, "utf8")) as Record<string, unknown>;
    return new Map(Object.entries(saved).map(([name, v]) => [name, isPoint(v) ? v : null]));
  } catch {
    return new Map();
  }
}

/** Last-week downloads per name; `null` for names npm doesn't know. Paced, checkpointed. */
async function weeklyDownloads(names: readonly string[]): Promise<Map<string, Point | null>> {
  const results = await loadCheckpoint();
  if (results.size > 0) console.error(`resuming from ${CHECKPOINT}: ${results.size} done`);
  const save = (): Promise<void> => writeFile(CHECKPOINT, JSON.stringify(Object.fromEntries(results)));
  const record = (name: string, value: unknown): void => {
    results.set(name, isPoint(value) && value.package === name ? value : null);
  };
  const todo = names.filter((n) => !results.has(n));
  const unscoped = todo.filter((n) => !n.startsWith("@"));
  const scoped = todo.filter((n) => n.startsWith("@"));

  for (let i = 0; i < unscoped.length; i += BULK_SIZE) {
    const batch = unscoped.slice(i, i + BULK_SIZE);
    const body = await getJson(`${DOWNLOADS}/${batch.join(",")}`);
    // A bulk response maps each name to its point, or null for an unknown package.
    for (const name of batch) record(name, typeof body === "object" && body !== null ? (body as Record<string, unknown>)[name] : undefined);
    await save();
    console.error(`unscoped: ${Math.min(i + BULK_SIZE, unscoped.length)}/${unscoped.length}`);
  }
  for (const [i, name] of scoped.entries()) {
    record(name, await getJson(`${DOWNLOADS}/${name}`));
    if ((i + 1) % 25 === 0 || i + 1 === scoped.length) {
      await save();
      if ((i + 1) % 100 === 0 || i + 1 === scoped.length) console.error(`scoped: ${i + 1}/${scoped.length}`);
    }
  }
  return results;
}

console.error(`range: ${RANGE} (pass --range ${RANGE} to resume on a later day); checkpoint: ${CHECKPOINT}`);
const names = await candidates(Math.ceil(limit * OVERFETCH));
const points = await weeklyDownloads(names);
const ranked = [...points.values()]
  .filter((p): p is Point => p !== null && p.downloads > 0)
  .toSorted((a, b) => b.downloads - a.downloads || (a.package < b.package ? -1 : 1))
  .slice(0, limit);
const weeks = new Set(ranked.map((p) => `${p.start}..${p.end}`));
if (weeks.size !== 1) throw new Error(`download counts span more than one week: ${[...weeks].join(", ")}`);
const [start, end] = [...weeks][0]!.split("..");

const header = {
  schemaVersion: 1,
  snapshot: new Date().toISOString().slice(0, 10),
  week: { start, end },
  license: "CC-BY-SA-4.0",
  source:
    "Names: top npm packages by downloads from ecosyste.ms (https://packages.ecosyste.ms, data CC BY-SA 4.0). " +
    "Counts: npm download-counts API, 7-day point totals (https://api.npmjs.org). Regenerate with scripts/update-popular.ts.",
};
// One package per line keeps diffs between snapshots readable.
const lines = ranked.map((p) => `    ${JSON.stringify({ name: p.package, weeklyDownloads: p.downloads })}`);
const json = `${JSON.stringify(header, null, 2).slice(0, -2)},\n  "packages": [\n${lines.join(",\n")}\n  ]\n}\n`;
JSON.parse(json); // sanity check
await writeFile(values.out, json);
console.error(`wrote ${ranked.length} packages (week ${start}..${end}) to ${values.out}`);
