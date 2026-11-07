const crypto = require("crypto");
const os = require("os");
module.exports = () => crypto.createHash("sha256").update(os.hostname()).digest("hex");
