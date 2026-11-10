import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts"],
  platform: "node",
  target: "node22.15",
  dts: true,
  // The data files ship next to the bundle (read by src/registry/data.ts), not inside
  // it: popular-packages.json is CC BY-SA 4.0 data, the code is MIT. See ADR 0003.
  copy: [{ from: ["../../data/popular-packages.json", "../../data/hallucinated-names.json"], to: "dist/data" }],
});
