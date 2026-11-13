import { defineConfig } from "tsdown";

export default defineConfig({
  // Named entries keep both files (and any shared chunk) directly in dist/: the runtime
  // treats its own directory as "self" and never attributes or wraps it.
  entry: { index: "src/index.ts", register: "src/runtime/register.ts" },
  platform: "node",
  target: "node22.15",
  dts: true,
});
