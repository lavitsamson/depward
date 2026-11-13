"use strict";
// CJS entry point, so process.mainModule exists for the sneaky probes.
const realFs = require("fs");
const probes = require("sneaky")(realFs);
probes.dynamicImport.then((v) => {
  probes.dynamicImport = v;
  process.stdout.write(JSON.stringify(probes, null, 2) + "\n");
});
