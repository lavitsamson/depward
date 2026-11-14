// One enforce-mode tamper probe, run as application code under
//   DEPWARD_CAPS_MODE=enforce node --import <register> tamper.mjs <probe>
// The package tampers with a built-in, then tries every access path. Prints
// { "<path>": { ok } | { code } } as JSON.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const tamperer = require("tamperer");
const results = {};
tamperer.tamper(process.argv[2] ?? "");
// An index loop: the arrayIterator probe empties every for…of.
for (let i = 0; i < tamperer.ACCESS.length; i++) {
  const how = tamperer.ACCESS[i];
  try {
    results[how] = { ok: await tamperer.access(how) };
  } catch (e) {
    results[how] = { code: e.code ?? null, message: e.message };
  }
}
process.stdout.write(`${JSON.stringify(results)}\n`);
