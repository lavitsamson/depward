// Near misses for child_process, env, native_addon, worker, crypto, and os_info.
const env = { NODE: 1, TOKEN: "x" };
const worker = { postMessage() {} };
const settings = { crypto: false, os: "linux" };
console.log("child_process", "bindings", "file.node", env.TOKEN, settings.crypto);
worker.postMessage(process.platform);
module.exports = { worker, settings, cluster: "none" };
