// Registry, cache, and config setup shared by the commands that talk to the registry.

import { createDiskCache, createRegistryClient, defaultCacheDir, loadConfig, type Cache, type DepwardConfig, type RegistryClient } from "@depward/core";
import { createUpdateDiff } from "@depward/diff";
import type { GateOptions, UpdateDiff } from "@depward/gate";
import type { Runtime } from "./runtime.ts";

/** What a registry-backed command needs. */
export interface CommandContext {
  config: DepwardConfig;
  registry: RegistryClient;
  /** Analysis results share the disk cache (ADR 0005); `undefined` when tests inject a registry. */
  analysisCache: Cache | undefined;
  /** Test overrides from {@link Runtime.gate} (registry, data files, clock). */
  overrides: Partial<GateOptions>;
}

/**
 * The gate's update path (M3.6, ADR 0006): diffs a request against the version locked
 * in `cwd`'s lockfiles. Uses the same registry, analysis cache, and test overrides as
 * the gate.
 */
export function updateDiff(cwd: string, registry: RegistryClient, analysisCache: Cache | undefined, overrides: Partial<GateOptions>): UpdateDiff {
  return createUpdateDiff({
    cwd,
    registry,
    ...(analysisCache === undefined ? {} : { analysisCache }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
    ...(overrides.tarLimits === undefined ? {} : { tarLimits: overrides.tarLimits }),
    ...(overrides.analyze === undefined ? {} : { analyze: overrides.analyze }),
  });
}

/** Loads the config and opens the registry client, honouring `--config` and `--offline`. */
export async function openContext(rt: Runtime, args: { config: string | undefined; offline: boolean }): Promise<CommandContext> {
  const config = await loadConfig(rt.cwd, args.config === undefined ? {} : { path: args.config });
  const cache = createDiskCache(defaultCacheDir(rt.env));
  const registry =
    rt.gate?.registry ??
    createRegistryClient({
      cwd: rt.cwd,
      env: rt.env,
      cache,
      ...(config.registry === undefined ? {} : { registry: config.registry }),
      ...(args.offline ? { offline: true } : {}),
    });
  return { config, registry, analysisCache: rt.gate?.registry ? undefined : cache, overrides: rt.gate ?? {} };
}
