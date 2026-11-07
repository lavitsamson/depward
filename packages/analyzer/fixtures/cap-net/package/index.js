const https = require("node:https");
exports.get = (u) => https.get(u);
exports.post = (u, body) => fetch(u, { method: "POST", body });
