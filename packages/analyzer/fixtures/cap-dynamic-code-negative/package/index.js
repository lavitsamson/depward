// Near miss: a method called eval, a timer with a function, and Function.prototype.
const engine = { eval(x) { return x; } };
function evaluate(x) { return engine.eval(x); }
const call = Function.prototype.call;
setTimeout(() => evaluate("eval"), 10);
module.exports = { evaluate, call };
