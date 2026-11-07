// Near miss: an IP literal never used in a network call (still an endpoint), and a loopback connect.
const net = require("net");
const DEFAULT_DNS = "203.0.113.53";
exports.isIp = (s) => net.isIP(s) !== 0;
exports.DEFAULT_DNS = DEFAULT_DNS;
exports.local = () => net.connect({ host: "127.0.0.1", port: 9229 });
