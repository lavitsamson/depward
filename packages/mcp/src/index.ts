/** The version of `@depward/mcp`. Kept in sync with package.json by `scripts/sync-versions.ts`. */
export const VERSION: string = "0.0.0";

export { createDepwardServer, decisionText, type DepwardServerOptions } from "./server.ts";
export { diffText } from "./diff.ts";
