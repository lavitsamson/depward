// Small AST helpers shared by the visitor. Pure.

import type * as acorn from "acorn";
import { propName } from "./bindings.ts";

type Node = acorn.AnyNode;

export const lineOf = (n: acorn.Node): number => n.loc?.start.line ?? 0;
export const isFunction = (n: Node): boolean =>
  n.type === "FunctionDeclaration" || n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression";
export const contains = (outer: acorn.Node, inner: acorn.Node): boolean => inner.start >= outer.start && inner.end <= outer.end;

/** Calls `cb` on every node under `root`, not descending into nested functions. */
export function shallow(root: Node, cb: (n: Node, parent: Node | undefined) => void, parent?: Node): void {
  cb(root, parent);
  for (const [key, value] of Object.entries(root)) {
    if (key === "loc") continue;
    const children: unknown[] = Array.isArray(value) ? value : [value];
    for (const c of children) {
      if (c && typeof c === "object" && typeof (c as { type?: unknown }).type === "string" && !isFunction(c as Node)) {
        shallow(c as Node, cb, root);
      }
    }
  }
}

export function identifiersIn(nodes: readonly Node[]): Set<string> {
  const out = new Set<string>();
  for (const n of nodes) shallow(n, (c) => c.type === "Identifier" && out.add(c.name));
  return out;
}

/** Dotted name of a simple callee such as `Object.keys` or `fetch`. */
export function calleeName(n: Node): string | undefined {
  if (n.type === "Identifier") return n.name;
  if (n.type === "MemberExpression" && n.object.type === "Identifier") {
    const p = propName(n);
    return p === undefined ? undefined : `${n.object.name}.${p}`;
  }
  return undefined;
}

export function propNameOf(n: Node): string | undefined {
  if (n.type === "Identifier") return n.name;
  return n.type === "Literal" && typeof n.value === "string" ? n.value : undefined;
}

/** A string literal, a template literal, or a `+` concatenation involving one. */
export function stringish(n: Node | undefined): boolean {
  if (!n) return false;
  if (n.type === "Literal") return typeof n.value === "string";
  if (n.type === "TemplateLiteral") return true;
  return n.type === "BinaryExpression" && n.operator === "+" && (stringish(n.left as Node) || stringish(n.right));
}
