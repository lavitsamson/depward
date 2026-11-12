import { defineConfig } from "vitest/config";

// Resolve workspace packages (`@depward/*`) to their TypeScript sources, so tests never
// depend on a stale build. Vitest runs tests in Vite's SSR environment, which takes its
// conditions from `ssr.resolve` rather than the top-level `resolve`.
const conditions = ["@depward/source", "module", "node", "import", "default"];

export default defineConfig({
  resolve: { conditions },
  ssr: { resolve: { conditions, externalConditions: ["@depward/source"] } },
  test: {
    projects: [
      {
        extends: true,
        test: { name: "unit", include: ["packages/*/test/**/*.test.ts", "action/test/**/*.test.ts"] },
      },
      {
        // Opt-in tests that hit the real npm registry. Run with `pnpm test:live`.
        extends: true,
        test: { name: "live", include: ["test/live/**/*.test.ts"], testTimeout: 60_000 },
      },
    ],
  },
});
