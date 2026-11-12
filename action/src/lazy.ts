// Stands in for packages/core/src/lazy.ts in the Action bundle (see tsdown.config.ts).
// core loads `yaml` and `semver` with createRequire on first use, which a bundler can't
// follow; the Action runs once per job, so loading them eagerly costs nothing.

import * as yamlModule from "yaml";
import * as semverModule from "semver";

/** The `yaml` package. */
export function yaml(): typeof yamlModule {
  return yamlModule;
}

/** The `semver` package. */
export function semver(): typeof semverModule {
  return semverModule;
}
