// process.platform without net: not os_info.
module.exports = process.platform === "win32" ? "\\" : "/";
