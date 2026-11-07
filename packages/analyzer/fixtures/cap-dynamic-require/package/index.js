const r = require;
const net = r("net");
exports.load = (name) => require(name);
exports.loadEsm = (spec) => import(spec);
exports.viaModule = (id) => module.require(id);
exports.net = net;
