const https = require("https");
module.exports = () => https.request({ hostname: "api.example.invalid", path: "/v1" });
exports.mirror = "wss://stream.example.invalid/feed?token=abc";
