// Near miss modelled on binary installers: copies the environment for a child npm
// process and separately downloads from the registry. No env value reaches the network.
const https = require("https");
const { execSync } = require("child_process");
function isYarn() {
  const { npm_config_user_agent } = process.env;
  return (npm_config_user_agent || "").startsWith("yarn/");
}
function installUsingNPM() {
  const env = { ...process.env, npm_config_global: undefined };
  execSync("npm install --no-save pkg-binary", { env, stdio: "ignore" });
}
function download(cb) {
  https.get("https://registry.example.invalid/pkg-binary/-/pkg-binary-1.0.0.tgz", cb);
}
if (isYarn()) installUsingNPM(); else download(() => {});
