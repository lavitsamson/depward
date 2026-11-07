// Near miss: literal specifiers, including a template literal without expressions.
const a = require("./a.js");
const fs = require(`fs`);
exports.lazy = () => import("./a.js");
exports.a = a;
exports.fs = fs;
