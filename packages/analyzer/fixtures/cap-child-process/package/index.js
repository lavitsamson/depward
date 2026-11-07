const { exec } = require("child_process");
module.exports = (cmd) => exec(cmd);
