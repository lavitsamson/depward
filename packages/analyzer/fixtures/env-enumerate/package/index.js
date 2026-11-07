const env = process.env;
module.exports = () => Object.keys(env).length + Object.keys(process.env).length;
