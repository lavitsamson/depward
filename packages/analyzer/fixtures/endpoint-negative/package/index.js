// Near miss: loopback, reserved, and documentation hosts are not reported.
const http = require("http");
const NS = "http://www.w3.org/2000/svg";
const DOCS = "https://developer.mozilla.org/en-US/docs/Web";
module.exports = () => [http.get("http://127.0.0.1:3000/health"), fetch("http://localhost:8080"), fetch("https://example.com"), NS, DOCS, "lib.utils.js"];
