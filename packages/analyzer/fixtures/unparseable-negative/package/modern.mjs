export const x = await Promise.resolve(1n ** 2n);
class A { #p = 1; static { this.y = 2; } get p() { return this.#p; } }
export { A };
