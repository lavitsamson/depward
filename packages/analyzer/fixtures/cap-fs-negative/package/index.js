// Near miss: a local module named fs, and "fs" only as a string.
const fsx = require("./fs");
console.log("fs", fsx.name);
