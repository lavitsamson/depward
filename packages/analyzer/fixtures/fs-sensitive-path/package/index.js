const fs = require("fs");
const os = require("os");
const path = require("path");
module.exports = () => fs.existsSync(path.join(os.homedir(), ".ssh", "id_rsa"));
