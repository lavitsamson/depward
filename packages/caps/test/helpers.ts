// Shared fixtures for the caps tests: synthetic, inert packages in the in-memory fake
// registry (endpoints use example.invalid only), and a package-lock.json writer.

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fakeRegistry, type FakeRegistry } from "../../diff/test/fake-registry.ts";

export { type FakeRegistry } from "../../diff/test/fake-registry.ts";

export const NOW: number = Date.parse("2026-11-13T22:30:00.000Z");

export function registry(): FakeRegistry {
  return fakeRegistry({
    "fx-files": { versions: { "1.0.0": { files: { "index.js": 'const fs = require("fs");\nmodule.exports = (p) => fs.readFileSync(p, "utf8");\n' } } } },
    "fx-net": {
      versions: {
        "1.0.0": { files: { "index.js": 'module.exports = () => fetch("https://api.example.invalid/v1");\n' } },
        "2.0.0": { files: { "index.js": 'const cp = require("child_process");\nmodule.exports = () => { cp.execSync("id"); return fetch("https://api.example.invalid/v2"); };\n' } },
      },
    },
    "fx-pure": { versions: { "1.0.0": {} } },
    "@fx/scoped": { versions: { "3.0.0": { files: { "index.js": "module.exports = process.env.HOME;\n" } } } },
  });
}

/** A lockfile entry: a registry version, or raw package-lock fields. */
export type Locked = string | { version?: string; resolved?: string; integrity?: string; link?: boolean };

/** Writes `dir/package-lock.json` (v3) locking `packages`. */
export async function lock(dir: string, reg: FakeRegistry, packages: Record<string, Locked>): Promise<void> {
  const out: Record<string, unknown> = { "": { name: "root" } };
  for (const [name, spec] of Object.entries(packages)) {
    if (typeof spec === "string") {
      const file = `${name.replace(/^@[^/]+\//, "")}-${spec}.tgz`;
      out[`node_modules/${name}`] = { version: spec, resolved: `https://registry.npmjs.org/${name}/-/${file}`, integrity: reg.integrity(name, spec) };
    } else {
      out[`node_modules/${name}`] = spec;
    }
  }
  await writeFile(join(dir, "package-lock.json"), JSON.stringify({ name: "root", lockfileVersion: 3, packages: out }, null, 2));
}
