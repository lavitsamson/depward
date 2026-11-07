// First pass over a file's AST: which names are bound to modules, to `require`, to
// `process.env`, or to string constants, and which names are declared at all (so a
// local `function fetch() {}` is not mistaken for the global).
//
// This is deliberately file-scoped, not lexically scoped: a name keeps its first
// binding wherever it appears. Real shadowing of `require`/`fs`-style names inside
// nested scopes is rare in published code, and erring towards "it's the module" means
// we over-report rather than miss a capability.

import { builtinModules } from "node:module";
import type * as acorn from "acorn";
import { full } from "acorn-walk";

/** What a name refers to. `module` is a normalized specifier (see {@link normalizeModule}). */
export type Binding =
  | { kind: "module"; module: string; member?: string }
  | { kind: "require" }
  | { kind: "env" }
  | { kind: "string"; value: string };

export interface FileScope {
  bindings: Map<string, Binding>;
  /** Every name declared anywhere in the file (variables, functions, params, classes, imports). */
  declared: Set<string>;
}

const BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/, "")));

/**
 * Normalizes a module specifier: builtins lose `node:` and their subpath (`node:fs/promises`
 * → `fs`), packages become their name (`@a/b/c` → `@a/b`), and relative paths are kept as is.
 */
export function normalizeModule(spec: string): string {
  if (spec.startsWith(".") || spec.startsWith("/")) return spec;
  const bare = spec.replace(/^node:/, "");
  const base = bare.split("/")[0] ?? bare;
  if (BUILTINS.has(bare) || BUILTINS.has(base)) return base;
  const segs = bare.split("/");
  return bare.startsWith("@") ? segs.slice(0, 2).join("/") : (segs[0] ?? bare);
}

/** True when the normalized name is a Node.js builtin module. */
export function isBuiltin(name: string): boolean {
  return BUILTINS.has(name);
}

/** The static string value of a node: string literals, template literals without expressions, and `+` of those. */
export function staticString(node: acorn.AnyNode | null | undefined, scope?: FileScope): string | undefined {
  if (!node) return undefined;
  switch (node.type) {
    case "Literal":
      return typeof node.value === "string" ? node.value : undefined;
    case "TemplateLiteral":
      return node.expressions.length === 0 ? (node.quasis[0]?.value.cooked ?? undefined) : undefined;
    case "BinaryExpression": {
      if (node.operator !== "+") return undefined;
      const l = staticString(node.left as acorn.AnyNode, scope);
      const r = l === undefined ? undefined : staticString(node.right, scope);
      return l !== undefined && r !== undefined ? l + r : undefined;
    }
    case "Identifier": {
      const b = scope?.bindings.get(node.name);
      return b?.kind === "string" ? b.value : undefined;
    }
    case "ParenthesizedExpression":
      return staticString(node.expression, scope);
    default:
      return undefined;
  }
}

/** A member expression's property name, when it is static (`a.b`, `a["b"]`). */
export function propName(node: acorn.MemberExpression): string | undefined {
  if (!node.computed) return node.property.type === "Identifier" ? node.property.name : undefined;
  return staticString(node.property as acorn.AnyNode);
}

/** Strips parentheses, `await`, and optional chaining wrappers. */
export function unwrap(node: acorn.AnyNode): acorn.AnyNode {
  let n = node;
  for (;;) {
    if (n.type === "ParenthesizedExpression" || n.type === "ChainExpression") n = n.expression;
    else if (n.type === "AwaitExpression") n = n.argument;
    else return n;
  }
}

/** True for `require` or a name bound to it. */
export function isRequireCallee(node: acorn.AnyNode, scope: FileScope): boolean {
  return node.type === "Identifier" && (node.name === "require" || scope.bindings.get(node.name)?.kind === "require");
}

/** True for `process.env` and `globalThis.process.env` (and `global.`). */
export function isProcessEnv(node: acorn.AnyNode): boolean {
  if (node.type !== "MemberExpression" || propName(node) !== "env") return false;
  const obj = node.object;
  if (obj.type === "Identifier") return obj.name === "process";
  return (
    obj.type === "MemberExpression" &&
    propName(obj) === "process" &&
    obj.object.type === "Identifier" &&
    (obj.object.name === "globalThis" || obj.object.name === "global")
  );
}

/** Resolves an expression to the module (and first member) it refers to, if any. */
export function resolveModule(node: acorn.AnyNode, scope: FileScope): { module: string; member?: string } | undefined {
  const n = unwrap(node);
  if (n.type === "CallExpression" && isRequireCallee(n.callee as acorn.AnyNode, scope)) {
    const spec = staticString(n.arguments[0] as acorn.AnyNode | undefined, scope);
    return spec === undefined ? undefined : { module: normalizeModule(spec) };
  }
  if (n.type === "ImportExpression") {
    const spec = staticString(n.source, scope);
    return spec === undefined ? undefined : { module: normalizeModule(spec) };
  }
  if (n.type === "Identifier") {
    const b = scope.bindings.get(n.name);
    return b?.kind === "module" ? (b.member === undefined ? { module: b.module } : { module: b.module, member: b.member }) : undefined;
  }
  if (n.type === "MemberExpression") {
    const base = resolveModule(n.object as acorn.AnyNode, scope);
    if (!base) return undefined;
    if (base.member !== undefined) return base;
    const member = propName(n);
    return member === undefined ? base : { module: base.module, member };
  }
  return undefined;
}

function bind(scope: FileScope, name: string, b: Binding): void {
  if (!scope.bindings.has(name)) scope.bindings.set(name, b);
}

function bindPattern(scope: FileScope, id: acorn.Pattern, init: acorn.AnyNode | null | undefined): void {
  if (!init) return;
  const value = unwrap(init);
  if (id.type === "Identifier") {
    if (value.type === "Identifier" && isRequireCallee(value, scope)) return bind(scope, id.name, { kind: "require" });
    if (isProcessEnv(value)) return bind(scope, id.name, { kind: "env" });
    const str = staticString(value, scope);
    if (str !== undefined) return bind(scope, id.name, { kind: "string", value: str });
    const mod = resolveModule(value, scope);
    if (mod) bind(scope, id.name, { kind: "module", ...mod });
    return;
  }
  if (id.type !== "ObjectPattern") return;
  const mod = resolveModule(value, scope);
  if (!mod) return;
  for (const p of id.properties) {
    if (p.type !== "Property") continue;
    const key = p.computed ? staticString(p.key as acorn.AnyNode) : p.key.type === "Identifier" ? p.key.name : staticString(p.key as acorn.AnyNode);
    const target = p.value.type === "AssignmentPattern" ? p.value.left : p.value;
    if (key === undefined || target.type !== "Identifier") continue;
    bind(scope, target.name, { kind: "module", module: mod.module, member: mod.member ?? key });
  }
}

function declarePattern(scope: FileScope, p: acorn.Pattern | null | undefined): void {
  if (!p) return;
  switch (p.type) {
    case "Identifier":
      scope.declared.add(p.name);
      break;
    case "ObjectPattern":
      for (const prop of p.properties) declarePattern(scope, prop.type === "Property" ? prop.value : prop.argument);
      break;
    case "ArrayPattern":
      for (const el of p.elements) declarePattern(scope, el);
      break;
    case "RestElement":
      declarePattern(scope, p.argument);
      break;
    case "AssignmentPattern":
      declarePattern(scope, p.left);
      break;
    default:
      break;
  }
}

/** Runs the binding pass over a parsed program. */
export function collectScope(program: acorn.Program): FileScope {
  const scope: FileScope = { bindings: new Map(), declared: new Set() };
  full(program, (node) => {
    switch (node.type) {
      case "VariableDeclarator":
        declarePattern(scope, node.id);
        bindPattern(scope, node.id, node.init);
        break;
      case "AssignmentExpression":
        if (node.operator === "=" && node.left.type === "Identifier") bindPattern(scope, node.left, node.right);
        break;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        if (node.type !== "ArrowFunctionExpression" && node.id) scope.declared.add(node.id.name);
        for (const p of node.params) declarePattern(scope, p);
        break;
      case "ClassDeclaration":
      case "ClassExpression":
        if (node.id) scope.declared.add(node.id.name);
        break;
      case "CatchClause":
        declarePattern(scope, node.param);
        break;
      case "ImportDeclaration": {
        const module = normalizeModule(String(node.source.value));
        for (const s of node.specifiers) {
          scope.declared.add(s.local.name);
          if (s.type === "ImportSpecifier") {
            const imported = s.imported.type === "Identifier" ? s.imported.name : String(s.imported.value);
            bind(scope, s.local.name, imported === "default" ? { kind: "module", module } : { kind: "module", module, member: imported });
          } else bind(scope, s.local.name, { kind: "module", module });
        }
        break;
      }
      default:
        break;
    }
  });
  return scope;
}
