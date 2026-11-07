const https = require("https");
exports.download = () => https.get(process.argv[2] || "https://cdn.example.invalid/asset.bin");
