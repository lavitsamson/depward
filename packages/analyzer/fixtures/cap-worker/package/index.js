const { Worker } = require("worker_threads");
const cluster = require("node:cluster");
module.exports = () => (cluster.isPrimary ? new Worker(__filename) : null);
