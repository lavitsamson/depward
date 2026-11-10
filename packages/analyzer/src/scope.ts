// Lexical scopes for intra-file value flow, following JavaScript's rules: a name is
// qualified by the innermost scope that declares it, so `e` in one minified function is
// not `e` in another, while a closure still shares its outer function's variables.
//
// Scopes are the program, functions (parameters, `var`, hoisted function
// declarations), and blocks, `for (let …)`, `catch (…)`, and `switch` bodies for
// `let` / `const` / `class` / block-level functions. Getting block scopes right matters
// for security: folding a `catch (t)` into its function would let a stealer split its
// own flow (and dodge `env-exfil-pattern`) just by adding `catch (t) {}`.

import type * as acorn from "acorn";
import { isFunction } from "./ast.ts";

type Node = acorn.AnyNode;

/** Adds the identifiers a binding pattern declares (`{ a, b: [c, ...d] = x }` → a, c, d). */
function patternNames(p: Node | null | undefined, out: Set<string>): void {
  if (!p) return;
  switch (p.type) {
    case "Identifier":
      out.add(p.name);
      return;
    case "ObjectPattern":
      for (const prop of p.properties) patternNames(prop.type === "RestElement" ? prop.argument : prop.value, out);
      return;
    case "ArrayPattern":
      for (const el of p.elements) patternNames(el, out);
      return;
    case "RestElement":
      patternNames(p.argument, out);
      return;
    case "AssignmentPattern":
      patternNames(p.left, out);
      return;
    default:
      return;
  }
}

/**
 * `var` declarations and function declarations anywhere in a function body except
 * nested functions (both hoist to the function; block functions also hoist in sloppy
 * mode). Only statement positions can declare, so expression trees are never walked,
 * which keeps this cheap on minified bundles.
 */
function hoistedNames(n: Node | null | undefined, out: Set<string>): void {
  if (!n) return;
  switch (n.type) {
    case "VariableDeclaration":
      if (n.kind === "var") for (const d of n.declarations) patternNames(d.id, out);
      return;
    case "FunctionDeclaration":
      if (n.id) out.add(n.id.name);
      return;
    case "BlockStatement":
      for (const s of n.body) hoistedNames(s, out);
      return;
    case "IfStatement":
      hoistedNames(n.consequent, out);
      hoistedNames(n.alternate, out);
      return;
    case "ForStatement":
      if (n.init?.type === "VariableDeclaration") hoistedNames(n.init, out);
      hoistedNames(n.body, out);
      return;
    case "ForInStatement":
    case "ForOfStatement":
      if (n.left.type === "VariableDeclaration") hoistedNames(n.left, out);
      hoistedNames(n.body, out);
      return;
    case "WhileStatement":
    case "DoWhileStatement":
    case "LabeledStatement":
    case "WithStatement":
      hoistedNames(n.body, out);
      return;
    case "TryStatement":
      hoistedNames(n.block, out);
      hoistedNames(n.handler?.body, out);
      hoistedNames(n.finalizer, out);
      return;
    case "SwitchStatement":
      for (const c of n.cases) for (const s of c.consequent) hoistedNames(s, out);
      return;
    case "ExportNamedDeclaration":
      hoistedNames(n.declaration, out);
      return;
    case "ExportDefaultDeclaration":
      if (n.declaration.type === "FunctionDeclaration") hoistedNames(n.declaration, out);
      return;
    default:
      return;
  }
}

/** `let` / `const` / `class` / function declarations directly in a statement list. */
function lexicalNames(statements: readonly Node[], out: Set<string>): void {
  for (const raw of statements) {
    let s: Node | null | undefined = raw;
    if (s.type === "ExportNamedDeclaration") s = s.declaration;
    else if (s.type === "ExportDefaultDeclaration") s = s.declaration;
    if (!s) continue;
    if (s.type === "VariableDeclaration" && s.kind !== "var") for (const d of s.declarations) patternNames(d.id, out);
    else if ((s.type === "ClassDeclaration" || s.type === "FunctionDeclaration") && s.id) out.add(s.id.name);
  }
}

/**
 * The names `n` declares if it opens a scope, else `null`. `parent` tells a function's
 * own body block (part of the function's scope) from a nested block.
 */
function scopeNames(n: Node, parent: Node | undefined): Set<string> | null {
  const out = new Set<string>();
  switch (n.type) {
    case "Program":
      for (const s of n.body) hoistedNames(s as Node, out);
      lexicalNames(n.body as Node[], out);
      return out;
    case "FunctionDeclaration":
    case "FunctionExpression":
    case "ArrowFunctionExpression":
      for (const p of n.params) patternNames(p, out);
      // A named function expression can refer to itself.
      if (n.type === "FunctionExpression" && n.id) out.add(n.id.name);
      if (n.body.type === "BlockStatement") {
        hoistedNames(n.body, out);
        lexicalNames(n.body.body, out);
      }
      return out;
    case "BlockStatement":
      if (parent && isFunction(parent)) return null;
      lexicalNames(n.body, out);
      return out;
    case "StaticBlock":
      hoistedNames({ type: "BlockStatement", body: n.body } as unknown as Node, out);
      lexicalNames(n.body, out);
      return out;
    case "ForStatement":
      if (n.init?.type === "VariableDeclaration" && n.init.kind !== "var") for (const d of n.init.declarations) patternNames(d.id, out);
      return out;
    case "ForInStatement":
    case "ForOfStatement":
      if (n.left.type === "VariableDeclaration" && n.left.kind !== "var") for (const d of n.left.declarations) patternNames(d.id, out);
      return out;
    case "CatchClause":
      patternNames(n.param, out);
      return out;
    case "SwitchStatement":
      for (const c of n.cases) lexicalNames(c.consequent, out);
      return out;
    default:
      return null;
  }
}

/** The scopes visible at one point, innermost first. Shared by every point in a scope. */
export interface ScopeChain {
  readonly ids: readonly number[];
  readonly names: readonly Set<string>[];
}

const EMPTY: ScopeChain = { ids: [], names: [] };

/** Resolves names to the scope that declares them. One instance per file. */
export class Scopes {
  // Keyed by the innermost scope node: every point inside a scope sees the same chain.
  private readonly chains = new WeakMap<Node, ScopeChain>();
  // Nodes known not to open a scope (or to open an empty one), so they're checked once.
  private readonly notScopes = new WeakSet<Node>();
  private nextId = 0;

  /** The scope chain at the end of `anc` (an ancestor chain, outermost first). */
  chain(anc: readonly Node[]): ScopeChain {
    for (let i = anc.length - 1; i >= 0; i--) {
      const n = anc[i] as Node;
      const hit = this.chains.get(n);
      if (hit) return hit;
      if (this.notScopes.has(n)) continue;
      const names = scopeNames(n, anc[i - 1]);
      if (names === null || (names.size === 0 && n.type !== "Program")) {
        this.notScopes.add(n);
        continue;
      }
      const outer = i === 0 ? EMPTY : this.chain(anc.slice(0, i));
      const chain = { ids: [this.nextId++, ...outer.ids], names: [names, ...outer.names] };
      this.chains.set(n, chain);
      return chain;
    }
    return EMPTY;
  }

  /**
   * `name` qualified by the innermost scope in `chain` that declares it. Undeclared
   * names (globals, implicit globals) share one file-wide scope.
   */
  static resolve(name: string, chain: ScopeChain): string {
    for (let i = 0; i < chain.names.length; i++) {
      if (chain.names[i]?.has(name)) return `${chain.ids[i]}:${name}`;
    }
    return `g:${name}`;
  }

  /** {@link Scopes.resolve} for every name in `names`. */
  static resolveAll(names: Iterable<string>, chain: ScopeChain): Set<string> {
    const out = new Set<string>();
    for (const n of names) out.add(Scopes.resolve(n, chain));
    return out;
  }

  /** `name` as seen from the end of `anc`. */
  qualify(name: string, anc: readonly Node[]): string {
    return Scopes.resolve(name, this.chain(anc));
  }

  /** Every name in `names` as seen from the end of `anc`. */
  qualifyAll(names: Iterable<string>, anc: readonly Node[]): Set<string> {
    return Scopes.resolveAll(names, this.chain(anc));
  }
}
