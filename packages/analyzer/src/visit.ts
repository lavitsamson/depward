// Second pass over a file's AST: records capability uses and the raw facts that the
// signal rules in analyze.ts turn into signals. Never evaluates anything.

import type * as acorn from "acorn";
import { fullAncestor } from "acorn-walk";
import {
  collectScope,
  isBuiltin,
  isProcessEnv,
  isRequireCallee,
  normalizeModule,
  propName,
  resolveModule,
  staticString,
  unwrap,
  type FileScope,
} from "./bindings.ts";
import { clean, countAsciiEscapes, findEndpoints, isEncodedBlob, isSensitiveEnvKey, sensitivePath, shannonEntropy, type FoundEndpoint } from "./text.ts";
import type { Capability } from "./types.ts";
import { callsNetObject, isNetCallNode, reaches, valueFlow, type FlowEdge } from "./flow.ts";
import { calleeName, contains, identifiersIn, isFunction, lineOf, propNameOf, rootIdentifier, shallow, stringish } from "./ast.ts";
import {
  BINDING_CAPS,
  DECODE_ENCODINGS,
  ENUMERATORS,
  GLOBAL_NET,
  GLOBAL_OBJECTS,
  HEX_ID,
  HTTP_CLIENTS,
  MODULE_CAPS,
  NATIVE_LOADERS,
  WRITE_FNS,
} from "./tables.ts";

type Node = acorn.AnyNode;

/** A located fact inside one file. */
export interface Hit {
  line: number;
  snippet?: string;
  detail?: string;
}

/** Everything the visitor learned about one JS file. */
export interface FileFacts {
  uses: { cap: Capability; line: number; evidence: string }[];
  envKeys: string[];
  envSensitive: Hit[];
  /** Sensitive env values that flow into a network call (env-exfil-pattern). */
  envExfil: Hit[];
  sensitivePaths: Hit[];
  endpoints: (FoundEndpoint & { line: number })[];
  rawIp: Hit[];
  obfuscation: string[];
  encodedPayloads: Hit[];
  highEntropy: Hit[];
  /** Relative module specifiers (`./lib/x`), for following install scripts. */
  localImports: string[];
}


/** Runs both passes over one parsed program. */
export function analyzeProgram(program: acorn.Program): FileFacts {
  const v = new Visitor(collectScope(program));
  fullAncestor(program, (node, _st, ancestors, type) => v.visit(node, ancestors, type));
  return v.finish();
}

class Visitor {
  readonly scope: FileScope;
  readonly facts: FileFacts = {
    uses: [], envKeys: [], envSensitive: [], envExfil: [], sensitivePaths: [], endpoints: [], rawIp: [],
    obfuscation: [], encodedPayloads: [], highEntropy: [], localImports: [],
  };
  private ids = 0;
  private hexIds = 0;
  private escapes = 0;
  private stringChars = 0;
  private readonly platformLines: number[] = [];
  private readonly rotations: { fn: Node; inLoop: boolean }[] = [];
  private readonly parseIntFns = new Set<Node>();
  private readonly decodes: { line: number; inSink: boolean; taint?: string; snippet: string }[] = [];
  private readonly sinks: Set<string>[] = [];
  private readonly edges: FlowEdge[] = [];
  // env-exfil-pattern: sensitive env values, network call arguments, and network objects.
  private readonly envSources: { line: number; detail: string; direct: boolean; viaObjects: string[]; taint?: string }[] = [];
  private readonly netSinks: Set<string>[] = [];
  private readonly netObjects = new Set<string>();
  private readonly objectCalls: { obj: string; idents: Set<string> }[] = [];

  constructor(scope: FileScope) {
    this.scope = scope;
  }

  private global(name: string): boolean {
    return !this.scope.declared.has(name);
  }

  private use(cap: Capability, node: acorn.Node, evidence: string): void {
    this.facts.uses.push({ cap, line: lineOf(node), evidence: clean(evidence, 80) });
  }

  visit(node: Node, anc: Node[], type: string): void {
    const parent = anc[anc.length - 2];
    switch (node.type) {
      case "Identifier":
        return this.identifier(node, anc, parent, type);
      case "MemberExpression":
        return this.member(node, anc);
      case "CallExpression":
      case "NewExpression":
        return this.call(node, anc);
      case "ImportDeclaration": {
        this.importSpec(String(node.source.value), node, `import "${String(node.source.value)}"`);
        const createReq = node.specifiers.some((s) => s.type === "ImportSpecifier" && propNameOf(s.imported) === "createRequire");
        if (createReq && normalizeModule(String(node.source.value)) === "module") this.use("dynamic_require", node, "createRequire");
        return;
      }
      case "ExportNamedDeclaration":
      case "ExportAllDeclaration":
        if (node.source) this.importSpec(String(node.source.value), node, `export from "${String(node.source.value)}"`);
        return;
      case "ImportExpression": {
        const spec = staticString(node.source, this.scope);
        if (spec === undefined) this.use("dynamic_require", node, "import(<expression>)");
        else this.importSpec(spec, node, `import("${spec}")`);
        return;
      }
      case "Literal":
        if (typeof node.value === "string") this.string(node.value, node.raw ?? "", node, parent);
        return;
      case "TemplateLiteral":
        for (const q of node.quasis) this.string(q.value.cooked ?? "", q.value.raw, q, parent, node);
        return;
      case "VariableDeclarator":
        if (node.id.type === "Identifier" && node.init) this.assigned(node.id.name, node.init);
        return;
      case "AssignmentExpression":
        if (node.left.type === "Identifier") this.assigned(node.left.name, node.right);
        return;
      default:
        return;
    }
  }

  private assigned(name: string, value: Node): void {
    this.edges.push({ to: name, from: identifiersIn([value]) });
    if (this.isNetCallNode(unwrap(value))) this.netObjects.add(name);
  }

  private identifier(node: acorn.Identifier, anc: Node[], parent: Node | undefined, type: string): void {
    this.ids++;
    if (HEX_ID.test(node.name)) this.hexIds++;
    if (type === "VariablePattern") return;
    const name = node.name;
    if (GLOBAL_NET.has(name) && this.global(name)) this.use("net", node, name);
    if (name === "eval" && this.global(name)) this.use("dynamic_code", node, "eval");
    if (this.scope.bindings.get(name)?.kind === "env" && parent) this.env(node, anc, name);
  }

  private member(node: acorn.MemberExpression, anc: Node[]): void {
    if (isProcessEnv(node)) return this.env(node, anc, "process.env");
    const prop = propName(node);
    if (prop === undefined) return;
    const obj = node.object;
    if (obj.type === "Identifier") {
      if (GLOBAL_OBJECTS.has(obj.name) && GLOBAL_NET.has(prop)) this.use("net", node, `${obj.name}.${prop}`);
      if (GLOBAL_OBJECTS.has(obj.name) && prop === "eval") this.use("dynamic_code", node, `${obj.name}.eval`);
      if (obj.name === "process" && (prop === "platform" || prop === "arch")) this.platformLines.push(lineOf(node));
      if (obj.name === "process" && prop === "dlopen") this.use("native_addon", node, "process.dlopen");
      if (obj.name === "module" && prop === "require") this.use("dynamic_require", node, "module.require");
    }
    if (prop === "createRequire" && resolveModule(obj as Node, this.scope)?.module === "module") {
      this.use("dynamic_require", node, "createRequire");
    }
  }

  private call(node: acorn.CallExpression | acorn.NewExpression, anc: Node[]): void {
    const callee = unwrap(node.callee as Node);
    const args = node.arguments as Node[];
    const name = calleeName(callee);
    const isNew = node.type === "NewExpression";

    if (!isNew && isRequireCallee(callee, this.scope)) {
      const spec = staticString(args[0], this.scope);
      if (spec === undefined) this.use("dynamic_require", node, `${name ?? "require"}(<expression>)`);
      else this.importSpec(spec, node, `require("${spec}")`);
    }
    const mod = resolveModule(callee, this.scope);
    if (!isNew && mod?.module === "module" && mod.member === "createRequire") this.use("dynamic_require", node, "createRequire()");
    if (name === "process.binding" || name === "process._linkedBinding") {
      const which = staticString(args[0], this.scope);
      const cap = which === undefined ? undefined : BINDING_CAPS[which];
      if (cap) this.use(cap, node, `process.binding("${which}")`);
    }
    if ((name === "Function" && this.global("Function")) || name === "globalThis.Function") {
      this.use("dynamic_code", node, isNew ? "new Function()" : "Function()");
    }
    if (!isNew && (name === "setTimeout" || name === "setInterval") && this.global(name) && stringish(args[0])) {
      this.use("dynamic_code", node, `${name}(<string>)`);
    }
    if (!isNew && callee.type === "MemberExpression" && propName(callee) === "constructor" && staticString(args[0], this.scope) !== undefined) {
      this.use("dynamic_code", node, ".constructor(<string>)");
    }
    if (name === "parseInt") for (const a of anc) if (isFunction(a)) this.parseIntFns.add(a);
    this.rotation(node, callee, args, anc);
    const isNet = this.isNetCallNode(node);
    if (isNet) this.rawIps(node, args);
    if (isNet || this.callsNetObject(callee)) this.netSinks.push(identifiersIn(args));
    else if (callee.type === "MemberExpression") {
      const root = rootIdentifier(callee);
      if (root !== undefined) this.objectCalls.push({ obj: root, idents: identifiersIn(args) });
    }
    this.decode(node, name, args, anc);
    if (this.isSink(node)) this.sinks.push(identifiersIn(args));
  }

  private importSpec(spec: string, node: acorn.Node, evidence: string): void {
    if (spec.startsWith(".") || spec.startsWith("/")) {
      this.facts.localImports.push(spec);
      if (/\.node$/i.test(spec)) this.use("native_addon", node, evidence);
      return;
    }
    const m = normalizeModule(spec);
    const cap = isBuiltin(m) ? MODULE_CAPS[m] : undefined;
    if (cap) this.use(cap, node, evidence);
    if (NATIVE_LOADERS.has(m)) this.use("native_addon", node, evidence);
    if (HTTP_CLIENTS.has(m)) this.use("net", node, evidence);
  }

  // --- process.env ---------------------------------------------------------------

  /** `node` is `process.env` or a name bound to it. */
  private env(node: Node, anc: Node[], label: string): void {
    const parent = anc[anc.length - 2];
    const grand = anc[anc.length - 3];
    if (parent?.type === "MemberExpression" && parent.object === node) {
      const key = propName(parent);
      if (key === undefined) return this.use("env", parent, `${label}[<expression>]`);
      const written =
        (grand?.type === "AssignmentExpression" && grand.left === parent) ||
        (grand?.type === "UnaryExpression" && grand.operator === "delete");
      return written ? this.use("env", parent, `${label}.${key} (write)`) : this.envRead(key, parent, anc.slice(0, -1));
    }
    if (parent?.type === "VariableDeclarator" && parent.init === node && parent.id.type === "ObjectPattern") return this.envPattern(parent.id);
    if (parent?.type === "AssignmentExpression" && parent.right === node && parent.left.type === "ObjectPattern") return this.envPattern(parent.left);
    if (parent?.type === "SpreadElement") return this.enumerate(node, `...${label}`, anc);
    if (parent?.type === "ForInStatement" && parent.right === node) return this.enumerate(node, `for…in ${label}`, anc);
    if (parent?.type === "CallExpression" && parent.arguments.includes(node as acorn.Expression)) {
      const fn = calleeName(unwrap(parent.callee as Node));
      if (fn !== undefined && ENUMERATORS.has(fn)) return this.enumerate(node, `${fn}(${label})`, anc);
    }
    if (label === "process.env") this.use("env", node, label);
  }

  /** `anc` ends with `node` for expression reads; destructuring passes `taint` (the target name) instead. */
  private envRead(key: string, node: acorn.Node, anc?: Node[], taint?: string): void {
    this.facts.envKeys.push(key);
    this.use("env", node, `process.env.${key}`);
    if (isSensitiveEnvKey(key)) this.sensitive(node, clean(`reads process.env.${key}`, 100), anc, taint);
  }

  /** Records a sensitive env value and where it flows: into a network call, an object method, or a variable. */
  private sensitive(node: acorn.Node, detail: string, anc: Node[] | undefined, taint?: string): void {
    const line = lineOf(node);
    this.facts.envSensitive.push({ line, detail });
    const { direct, viaObjects, flow } = valueFlow(node, anc ?? [], this.scope);
    const target = taint ?? flow;
    this.envSources.push({ line, detail, direct, viaObjects, ...(target === undefined ? {} : { taint: target }) });
  }

  private envPattern(p: acorn.ObjectPattern): void {
    for (const prop of p.properties) {
      if (prop.type === "RestElement") {
        this.enumerate(prop, "rest destructuring of process.env", undefined, prop.argument.type === "Identifier" ? prop.argument.name : undefined);
      }
      else {
        const key = prop.computed ? staticString(prop.key as Node, this.scope) : propNameOf(prop.key as Node);
        const target = prop.value.type === "AssignmentPattern" ? prop.value.left : prop.value;
        if (key !== undefined) this.envRead(key, prop, undefined, target.type === "Identifier" ? target.name : undefined);
        else this.use("env", prop, "process.env[<expression>]");
      }
    }
  }

  private enumerate(node: acorn.Node, how: string, anc?: Node[], taint?: string): void {
    this.use("env", node, how);
    this.sensitive(node, clean(`enumerates process.env (${how})`, 100), anc, taint);
  }

  // --- strings ---------------------------------------------------------------------

  private string(value: string, raw: string, node: acorn.Node, parent: Node | undefined, self: Node = node as Node): void {
    if (value.length === 0) return;
    this.stringChars += value.length;
    this.escapes += countAsciiEscapes(raw);
    const line = lineOf(node);
    const what = sensitivePath(value);
    if (what) this.facts.sensitivePaths.push({ line, snippet: clean(value), detail: what });
    const hostContext =
      parent?.type === "Property" && parent.value === self && ["host", "hostname"].includes(propNameOf(parent.key as Node) ?? "");
    for (const ep of findEndpoints(value, hostContext)) this.facts.endpoints.push({ ...ep, line });
    if (value.length > 200) {
      const h = shannonEntropy(value);
      if (h > 5.2) this.facts.highEntropy.push({ line, snippet: clean(value, 60), detail: `${value.length} chars, entropy ${h.toFixed(2)}` });
    }
  }

  // --- network calls -----------------------------------------------------------------

  private isNetCallNode(n: Node): boolean {
    return isNetCallNode(n, this.scope);
  }

  private callsNetObject(callee: Node): boolean {
    return callsNetObject(callee, this.scope);
  }

  private rawIps(node: acorn.Node, args: Node[]): void {
    for (const arg of args) {
      shallow(arg, (n, parent) => {
        const s = n.type === "Literal" || n.type === "Identifier" || n.type === "TemplateLiteral" ? staticString(n, this.scope) : undefined;
        if (s === undefined) return;
        const hostCtx = parent?.type === "Property" && ["host", "hostname"].includes(propNameOf(parent.key as Node) ?? "");
        for (const ep of findEndpoints(s, hostCtx)) {
          if (ep.ip) this.facts.rawIp.push({ line: lineOf(node), snippet: clean(ep.endpoint) });
        }
      });
    }
  }

  // --- encoded payloads ----------------------------------------------------------------

  private decode(node: acorn.CallExpression | acorn.NewExpression, name: string | undefined, args: Node[], anc: Node[]): void {
    const isBufferFrom = name === "Buffer.from" || (node.type === "NewExpression" && name === "Buffer");
    const isAtob = node.type === "CallExpression" && (name === "atob" || name === "globalThis.atob");
    if (!isBufferFrom && !isAtob) return;
    if (isBufferFrom && !DECODE_ENCODINGS.has(staticString(args[1], this.scope) ?? "")) return;
    const blob = staticString(args[0], this.scope);
    if (blob === undefined || !isEncodedBlob(blob)) return;
    let inSink = false;
    let taint: string | undefined;
    for (let i = anc.length - 2; i >= 0; i--) {
      const a = anc[i];
      if (!a || isFunction(a)) break;
      if ((a.type === "CallExpression" || a.type === "NewExpression") && this.isSink(a) && (a.arguments as Node[]).some((x) => contains(x, node))) {
        inSink = true;
        break;
      }
      if (a.type === "VariableDeclarator" && a.id.type === "Identifier") taint ??= a.id.name;
      if (a.type === "AssignmentExpression" && a.left.type === "Identifier") taint ??= a.left.name;
    }
    this.decodes.push({ line: lineOf(node), inSink, ...(taint === undefined ? {} : { taint }), snippet: `${name ?? "decode"}(<${blob.length}-char literal>)` });
  }

  private isSink(call: Node): boolean {
    if (call.type !== "CallExpression" && call.type !== "NewExpression") return false;
    const callee = unwrap(call.callee as Node);
    if (callee.type === "Identifier" && (callee.name === "eval" || callee.name === "Function") && this.global(callee.name)) return true;
    const mod = resolveModule(callee, this.scope);
    if (mod?.module === "vm") return true;
    const fn = callee.type === "Identifier" ? (mod?.member ?? callee.name) : callee.type === "MemberExpression" ? propName(callee) : undefined;
    return fn !== undefined && (WRITE_FNS.has(fn) || fn === "_compile");
  }

  // --- obfuscation -----------------------------------------------------------------------

  private rotation(node: acorn.CallExpression | acorn.NewExpression, callee: Node, args: Node[], anc: Node[]): void {
    if (node.type !== "CallExpression" || callee.type !== "MemberExpression" || propName(callee) !== "push") return;
    const arr = callee.object;
    const inner = args[0] ? unwrap(args[0]) : undefined;
    if (arr.type !== "Identifier" || inner?.type !== "CallExpression") return;
    const ic = unwrap(inner.callee as Node);
    if (ic.type !== "MemberExpression" || propName(ic) !== "shift" || ic.object.type !== "Identifier" || ic.object.name !== arr.name) return;
    const fn = anc.findLast(isFunction) ?? anc[0];
    const inLoop = anc.some((a) => a.type === "WhileStatement" || a.type === "DoWhileStatement" || a.type === "ForStatement");
    if (fn) this.rotations.push({ fn, inLoop });
  }

  finish(): FileFacts {
    const f = this.facts;
    if (this.rotations.some((r) => r.inLoop && this.parseIntFns.has(r.fn))) f.obfuscation.push("string-array rotation (push/shift loop with parseInt)");
    if (this.ids >= 10 && this.hexIds / this.ids > 0.3) {
      f.obfuscation.push(`${Math.round((100 * this.hexIds) / this.ids)}% of identifiers look like _0x…`);
    }
    if (this.escapes >= 32 && this.escapes / Math.max(1, this.stringChars) >= 0.3) {
      f.obfuscation.push(`${this.escapes} \\x/\\u escapes of printable ASCII in string literals`);
    }
    for (const d of this.decodes) {
      if (d.inSink || (d.taint !== undefined && reaches(d.taint, this.edges, this.sinks))) {
        f.encodedPayloads.push({ line: d.line, snippet: d.snippet, detail: "decoded and passed to eval, Function, vm, or a write call" });
      }
    }
    const netSinks = [...this.netSinks, ...this.objectCalls.filter((c) => this.netObjects.has(c.obj)).map((c) => c.idents)];
    for (const s of this.envSources) {
      const flows = s.direct || s.viaObjects.some((o) => this.netObjects.has(o)) || (s.taint !== undefined && reaches(s.taint, this.edges, netSinks));
      if (flows) f.envExfil.push({ line: s.line, detail: `${s.detail}, which flows into a network call` });
    }
    if (f.uses.some((u) => u.cap === "net")) {
      for (const line of this.platformLines) f.uses.push({ cap: "os_info", line, evidence: "process.platform/arch with net" });
    }
    return f;
  }


}

