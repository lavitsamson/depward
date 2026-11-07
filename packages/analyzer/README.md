# @depward/analyzer

Statically profiles an npm package tarball: what it *can* do (filesystem, network, child
processes, env access, dynamic code, native addons) and which risk signals it shows
(install scripts, token-exfiltration shapes, obfuscation, encoded payloads, …). It
parses JavaScript with [acorn](https://github.com/acornjs/acorn) and **never executes
package code**.

## Example

```js
import { createRegistryClient, readTarball } from "@depward/core";
import { analyzePackage, profileFindings } from "@depward/analyzer";

const registry = createRegistryClient();
const meta = await registry.versionMeta("left-pad", "1.3.0");
if (!meta) throw new Error("not found");
const files = readTarball(await registry.tarball(meta)); // integrity-checked, in memory

const profile = analyzePackage(files);
console.log(profile.scripts, profile.endpoints);
for (const f of profileFindings(profile)) console.log(f.severity, f.id, f.message);
```

`profile.capabilities` maps each capability to where it is used. `profile.signals` lists
the risk signals, sorted by severity. Every signal ID is documented in
[`docs/findings.md`](../../docs/findings.md). The rules are in
[`docs/specs/analyzer.md`](../../docs/specs/analyzer.md).

Requires Node.js >= 22.15. ESM only. MIT licensed.
