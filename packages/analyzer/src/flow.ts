// Network-call recognition and intra-file value flow. Pure helpers used by the visitor.

import type * as acorn from "acorn";
import { calleeName, contains, isFunction, rootIdentifier } from "./ast.ts";
import { resolveModule, unwrap, type FileScope } from "./bindings.ts";
import { GLOBAL_NET, GLOBAL_OBJECTS, NET_MODULES } from "./tables.ts";

type Node = acorn.AnyNode;

/** A variable assignment: `to` receives a value built from the names in `from`. */
export interface FlowEdge {
  to: string;
  from: Set<string>;
}

/**
 * True for a call or `new` that talks to the network: a net builtin or known HTTP client
 * (`https.get`, `axios.post`, `require("https").request`), global `fetch`, or
 * `new WebSocket` / `XMLHttpRequest` / `EventSource` (also via `globalThis.`).
 */
export function isNetCallNode(n: Node, scope: FileScope): boolean {
  if (n.type !== "CallExpression" && n.type !== "NewExpression") return false;
  const callee = unwrap(n.callee as Node);
  const mod = resolveModule(callee, scope);
  if (mod && NET_MODULES.has(mod.module)) return true;
  const isNew = n.type === "NewExpression";
  if (callee.type === "Identifier") {
    return GLOBAL_NET.has(callee.name) && !scope.declared.has(callee.name) && (isNew || callee.name === "fetch");
  }
  const [obj, prop] = (calleeName(callee) ?? "").split(".");
  return obj !== undefined && GLOBAL_OBJECTS.has(obj) && prop !== undefined && GLOBAL_NET.has(prop);
}

/** True for `https.request(o).end`-style callees: a member chain built on a network call. */
export function callsNetObject(callee: Node, scope: FileScope): boolean {
  let o: Node = callee;
  for (let depth = 0; depth < 20; depth++) {
    if (o.type === "MemberExpression") o = unwrap(o.object as Node);
    else if (o.type === "CallExpression") {
      if (isNetCallNode(o, scope)) return true;
      o = unwrap(o.callee as Node);
    } else return false;
  }
  return false;
}

/** True when a value assigned to `name` flows (through variable assignments) into one of `sinks`. */
export function reaches(name: string, edges: readonly FlowEdge[], sinks: readonly Set<string>[]): boolean {
  const tainted = new Set([name]);
  for (let changed = true; changed; ) {
    changed = false;
    for (const e of edges) {
      if (!tainted.has(e.to) && [...e.from].some((x) => tainted.has(x))) {
        tainted.add(e.to);
        changed = true;
      }
    }
  }
  return sinks.some((s) => [...s].some((x) => tainted.has(x)));
}

/** Where a value goes, judged from its ancestors up to the enclosing function. */
export interface ValueFlow {
  /** It is (part of) an argument of a network call. */
  direct: boolean;
  /** Roots of member calls it is passed to (`req` in `req.end(v)`); network objects if assigned from a network call. */
  viaObjects: string[];
  /** The variable it is assigned to (or the `for…in` variable), if any. */
  flow?: string;
}

/** `anc` is the ancestor chain ending with `node`. */
export function valueFlow(node: acorn.Node, anc: readonly Node[], scope: FileScope): ValueFlow {
  let direct = false;
  const viaObjects: string[] = [];
  let flow: string | undefined;
  for (let i = anc.length - 2; i >= 0 && !direct; i--) {
    const a = anc[i];
    if (!a || isFunction(a)) break;
    if ((a.type === "CallExpression" || a.type === "NewExpression") && (a.arguments as Node[]).some((x) => contains(x, node))) {
      const callee = unwrap(a.callee as Node);
      if (isNetCallNode(a, scope) || callsNetObject(callee, scope)) direct = true;
      else if (callee.type === "MemberExpression") {
        const root = rootIdentifier(callee);
        if (root !== undefined) viaObjects.push(root);
      }
    }
    if (a.type === "VariableDeclarator" && a.id.type === "Identifier") flow ??= a.id.name;
    if (a.type === "AssignmentExpression" && a.left.type === "Identifier") flow ??= a.left.name;
    if (a.type === "ForInStatement" && a.left.type === "VariableDeclaration") {
      const id = a.left.declarations[0]?.id;
      if (id?.type === "Identifier") flow ??= id.name;
    }
  }
  return flow === undefined ? { direct, viaObjects } : { direct, viaObjects, flow };
}
