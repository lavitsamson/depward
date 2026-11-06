import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts", "src/testing.ts"],
  platform: "node",
  target: "node22.15",
  dts: true,
});
