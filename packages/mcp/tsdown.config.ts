import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts", "src/bin.ts"],
  platform: "node",
  target: "node22.15",
  dts: true,
});
