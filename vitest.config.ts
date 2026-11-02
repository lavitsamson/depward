import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { conditions: ["@depward/source"] },
  test: {
    projects: [
      {
        extends: true,
        test: { name: "unit", include: ["packages/*/test/**/*.test.ts"] },
      },
      {
        // Opt-in tests that hit the real npm registry. Run with `pnpm test:live`.
        extends: true,
        test: { name: "live", include: ["test/live/**/*.test.ts"], testTimeout: 60_000 },
      },
    ],
  },
});
