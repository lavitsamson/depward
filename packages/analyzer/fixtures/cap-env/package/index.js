// Near miss for env-sensitive-read: none of these keys are sensitive.
const mode = process.env.NODE_ENV;
const home = process.env["HOME"];
const { PORT } = process.env;
module.exports = { mode, home, PORT };
