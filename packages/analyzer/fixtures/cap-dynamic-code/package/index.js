const vm = require("vm");
exports.a = () => eval("1 + 1");
exports.b = new Function("a", "return a");
exports.c = () => setTimeout("tick()", 10);
exports.d = () => vm.runInNewContext("2 + 2");
