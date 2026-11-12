import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defineConfig } from "tsdown";

// One self-contained file for the Actions runner (docs/specs/diff.md § GitHub Action):
// every dependency is bundled, and the result is committed in dist/. CI rebuilds it and
// fails when it differs, so the committed bundle always matches the sources.
const eagerLazy = fileURLToPath(new URL("./src/lazy.ts", import.meta.url));

export default defineConfig({
  entry: { index: "src/main.ts" },
  platform: "node",
  target: "node24",
  format: "esm",
  outDir: "dist",
  dts: false,
  hash: false,
  clean: true,
  fixedExtension: true,
  deps: { alwaysBundle: [/.*/], onlyBundle: false },
  // One file: the analyzer is imported lazily (gate preloadAnalyzer), which would split it out.
  outputOptions: { codeSplitting: false },
  // Workspace packages resolve to their TypeScript sources, as in the tests.
  inputOptions: { resolve: { conditionNames: ["@depward/source", "import", "node", "default"] } },
  plugins: [
    {
      // core's lazy.ts uses createRequire, which the bundler can't follow.
      name: "depward-eager-lazy",
      resolveId(source: string, importer: string | undefined) {
        if (source === "../lazy.ts" && importer !== undefined && /[\\/]packages[\\/]core[\\/]src[\\/]/.test(importer)) return eagerLazy;
        return null;
      },
    },
  ],
  // The data files ship next to the bundle, where gate's data.ts looks for them
  // (popular-packages.json is CC BY-SA 4.0; see data/README.md and ADR 0003).
  copy: [{ from: ["../data/popular-packages.json", "../data/hallucinated-names.json", "../data/README.md"], to: "dist/data" }],
  hooks: { "build:done": writeLicenses },
});

// Bundled third-party code keeps its license notices: one file next to the bundle.
const BUNDLED: [name: string, from: string][] = [
  ["acorn", "../packages/analyzer/node_modules/acorn"],
  ["acorn-walk", "../packages/analyzer/node_modules/acorn-walk"],
  ["semver", "node_modules/semver"],
  ["yaml", "node_modules/yaml"],
];

const here = (p: string): URL => new URL(p, import.meta.url);

async function writeLicenses(): Promise<void> {
  const parts = ["depward GitHub Action bundle (dist/index.mjs): third-party licenses", "", "depward itself:", "", await readFile(here("../LICENSE"), "utf8")];
  for (const [name, dir] of BUNDLED) {
    const { version } = JSON.parse(await readFile(here(`${dir}/package.json`), "utf8")) as { version: string };
    parts.push("-".repeat(78), `${name}@${version}`, "", await readFile(here(`${dir}/LICENSE`), "utf8"));
  }
  const text = `${parts.map((p) => p.replace(/\r\n/g, "\n").trimEnd()).join("\n")}\n`;
  await writeFile(here("dist/THIRD_PARTY_LICENSES.txt"), text, "utf8");
}
