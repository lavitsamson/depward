# @depward/diff

Behavioral diff between two versions of an npm package. It catches malicious updates to
packages you already trust: a patch that suddenly adds a `postinstall`, starts using the
network, reads tokens, or ships an obfuscated file. Package code is never run. Both
versions are analyzed statically, in memory.

> **Status:** Phase 3 in progress. `diffPackages` is available. Lockfile mode, the CLI,
> and the GitHub Action are coming; see the [roadmap](../../docs/ROADMAP.md).

## Example

```js
import { createRegistryClient, readTarball } from "@depward/core";
import { analyzePackage } from "@depward/analyzer";
import { diffPackages } from "@depward/diff";

const registry = createRegistryClient();
const packument = await registry.packument("left-pad");
if (!packument) throw new Error("left-pad not found");

async function side(version) {
  const meta = await registry.versionMeta("left-pad", version);
  if (!meta) throw new Error(`left-pad@${version} not found`);
  return { meta, profile: analyzePackage(readTarball(await registry.tarball(meta))) };
}

const a = await side("1.2.0");
const b = await side("1.3.0");
const diff = diffPackages(a.profile, b.profile, a.meta, b.meta, { packument, now: Date.now() });

console.log(`${diff.name} ${diff.from} → ${diff.to}: ${diff.risk}`);
console.log(diff.capabilityDelta, diff.scriptDelta, diff.dependencyDelta);
for (const f of diff.findings) console.log(f.severity, f.id, f.message);
```

`risk` is the highest finding severity. Two or more `high` findings raise it to
`critical`. Every finding ID is documented in
[`docs/findings.md`](../../docs/findings.md#diff-depwarddiff), and the rules are in
[`docs/specs/diff.md`](../../docs/specs/diff.md).

Requires Node.js >= 22.15. ESM only. MIT licensed.
