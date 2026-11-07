const fs = require("fs");
module.exports = (p) => fs.readFileSync(p, "utf8");
