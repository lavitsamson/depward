// Loads the checked-in data files (data/*.json at the repository root; ADR 0003).
// The build copies them to dist/data/ so they ship as separate files: the popular list
// is CC BY-SA 4.0 data and stays out of the MIT-licensed JavaScript bundle.

import { readFile } from "node:fs/promises";
import { DepwardError, assertPackageName } from "@depward/core";
import { createPopularIndex, type PopularIndex, type PopularPackage } from "./typosquat.ts";

/** One entry of `data/hallucinated-names.json`. */
export interface HallucinatedName {
  readonly name: string;
  readonly ecosystem: string;
  /** `YYYY-MM-DD`. */
  readonly firstSeen: string;
  /** Public URL documenting the hallucination. */
  readonly source: string;
  /** The real package the model probably meant. */
  readonly suggestion: string;
}

/** The data the registry checks run against. */
export interface GateData {
  readonly popular: PopularIndex;
  /** Keyed by lower-cased name. */
  readonly hallucinated: ReadonlyMap<string, HallucinatedName>;
}

/** Builds {@link GateData} from in-memory lists, for tests and custom data sets. */
export function createGateData(popular: readonly PopularPackage[], hallucinated: readonly HallucinatedName[]): GateData {
  return {
    popular: createPopularIndex(popular),
    hallucinated: new Map(hallucinated.filter((h) => h.ecosystem === "npm").map((h) => [h.name.toLowerCase(), h])),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalid(file: string, why: string): DepwardError {
  return new DepwardError("INTERNAL", `data file ${file} is invalid: ${why}`);
}

/** Validates the contents of `popular-packages.json`. */
export function parsePopular(doc: unknown): PopularPackage[] {
  if (!isRecord(doc) || doc["schemaVersion"] !== 1 || !Array.isArray(doc["packages"])) {
    throw invalid("popular-packages.json", "expected schemaVersion 1 with a packages array");
  }
  return doc["packages"].map((p: unknown) => {
    if (!isRecord(p) || typeof p["name"] !== "string" || typeof p["weeklyDownloads"] !== "number") {
      throw invalid("popular-packages.json", "bad package entry");
    }
    assertPackageName(p["name"]);
    return { name: p["name"], weeklyDownloads: p["weeklyDownloads"] };
  });
}

/** Validates the contents of `hallucinated-names.json`. */
export function parseHallucinated(doc: unknown): HallucinatedName[] {
  if (!isRecord(doc) || doc["schemaVersion"] !== 1 || !Array.isArray(doc["entries"])) {
    throw invalid("hallucinated-names.json", "expected schemaVersion 1 with an entries array");
  }
  return doc["entries"].map((e: unknown) => {
    const fields = ["name", "ecosystem", "firstSeen", "source", "suggestion"] as const;
    if (!isRecord(e) || !fields.every((f) => typeof e[f] === "string")) {
      throw invalid("hallucinated-names.json", "bad entry");
    }
    const [name, ecosystem, firstSeen, source, suggestion] = fields.map((f) => e[f] as string) as [string, string, string, string, string];
    assertPackageName(name);
    assertPackageName(suggestion);
    return { name, ecosystem, firstSeen, source, suggestion };
  });
}

/**
 * Directory holding the data files. A built package reads `dist/data/`. When running
 * from TypeScript sources inside this repository, it reads the repository's `data/`.
 * The source-mode path is only used for `.ts` modules, so an installed package never
 * looks outside its own directory.
 */
function dataDir(): URL {
  return import.meta.url.endsWith(".ts") ? new URL("../../../../data/", import.meta.url) : new URL("./data/", import.meta.url);
}

async function readJson(file: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(new URL(file, dataDir()), "utf8"));
  } catch (cause) {
    throw new DepwardError("INTERNAL", `could not read data file ${file}`, { cause });
  }
}

let loaded: Promise<GateData> | undefined;

/** Loads the bundled data files once per process. */
export function loadGateData(): Promise<GateData> {
  if (loaded === undefined) {
    const p = (async () => {
      const [popular, hallucinated] = await Promise.all([readJson("popular-packages.json"), readJson("hallucinated-names.json")]);
      return createGateData(parsePopular(popular), parseHallucinated(hallucinated));
    })();
    loaded = p;
    // Don't remember a failure, so a later call can retry.
    p.catch(() => {
      if (loaded === p) loaded = undefined;
    });
  }
  return loaded;
}
