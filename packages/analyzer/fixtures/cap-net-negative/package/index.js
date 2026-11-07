// Near miss: a locally defined fetch, a non-network package, and "http" as a string.
function fetch(key) { return cache.get(key); }
const cache = new Map();
const createError = require("http-errors");
exports.load = (k) => fetch(k) ?? createError(404, "http");
