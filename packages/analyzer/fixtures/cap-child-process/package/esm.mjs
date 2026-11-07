import * as cp from "node:child_process";
export const run = () => cp.spawnSync("git", ["status"]);
