// Rewrites `export const VERSION: string = "..."` in each package's src/index.ts to match
// its package.json. Runs after `changeset version` (see the root `version-packages` script).
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const packagesDir = new URL("../packages/", import.meta.url);
const pattern = /export const VERSION: string = "[^"]*";/;

for (const dir of readdirSync(packagesDir)) {
  const base = new URL(`${dir}/`, packagesDir);
  const { version } = JSON.parse(readFileSync(new URL("package.json", base), "utf8")) as { version: string };
  const indexPath = new URL("src/index.ts", base);
  const source = readFileSync(indexPath, "utf8");
  if (!pattern.test(source)) throw new Error(`no VERSION constant in ${join("packages", dir, "src/index.ts")}`);
  const next = source.replace(pattern, `export const VERSION: string = ${JSON.stringify(version)};`);
  if (next !== source) writeFileSync(indexPath, next);
}
