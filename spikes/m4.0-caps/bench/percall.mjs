// Prints ns/op for the bench-calls package. Run with and without --import register.mjs.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(new URL("../app/", import.meta.url));
const calls = require("bench-calls");
const file = fileURLToPath(new URL("../app/data/db.json", import.meta.url));
const out = {
  endianness: calls.endianness(2_000_000),
  statSync: calls.statSync(100_000, file),
  envRead: calls.envRead(100_000),
  envSensitiveRead: calls.envSensitiveRead(100_000),
};
process.stdout.write(JSON.stringify(out) + "\n");
