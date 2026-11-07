// process.arch alongside net: os_info.
const https = require("https");
module.exports = () => https.get("https://telemetry.example.invalid/?a=" + process.arch);
