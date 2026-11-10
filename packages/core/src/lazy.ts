// Third-party modules loaded on first use, not at import time. `yaml` and `semver` cost
// about 130 ms and 75 ms to load, and the gate's hook runs once per agent shell command:
// a command with nothing to install needs neither. Both ship CommonJS for Node, so a
// synchronous require keeps the callers synchronous.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

type Yaml = typeof import("yaml");
type Semver = typeof import("semver");

let yamlModule: Yaml | undefined;
let semverModule: Semver | undefined;

/** The `yaml` package (pnpm and yarn-berry lockfiles). */
export function yaml(): Yaml {
  return (yamlModule ??= require("yaml") as Yaml);
}

/** The `semver` package (range resolution). */
export function semver(): Semver {
  return (semverModule ??= require("semver") as Semver);
}
