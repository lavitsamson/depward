// Policy engine: turns findings and failed lookups into allow / ask / deny.
// Spec: docs/specs/gate.md §Policy engine.
//
// Per finding, in order:
//   1. the default action for its ID (actions.ts)
//   2. escalations: low-downloads + package-too-new → deny both; install-script with
//      either of those → deny; two or more high `diff-*` findings → deny them (the
//      diff's own "two highs make critical" risk rule); any critical finding → deny
//   3. the config's `policy` override for the ID, which beats the escalations: an
//      explicit choice in the project's config is the user's call
//   4. the `allow` / `deny` lists. `deny` wins when both match. A denied package also
//      gets a `denylisted` finding, so reports always show why
// Package decision = the strictest finding action, and `onError` when a lookup failed
// (never for allow-listed packages). Command decision = the strictest package.

import {
  defaultConfig,
  findingDocsUrl,
  type DepwardConfig,
  type DepwardError,
  type Finding,
  type PolicyAction,
} from "@depward/core";
import { defaultAction, strictest } from "./actions.ts";
import { compileList, type ListMatch, type ListMatcher } from "./lists.ts";

/** Where a finding's action came from. */
export type ActionSource = "default" | "escalation" | "config" | "allow-list" | "deny-list";

/** A finding together with the action the policy assigned to it. */
export interface DecidedFinding {
  readonly finding: Finding;
  readonly action: PolicyAction;
  readonly source: ActionSource;
}

/** What {@link Policy.decidePackage} needs about one package. */
export interface PackageEvidence {
  readonly name: string;
  /** The resolved version, or `null` if none resolved. */
  readonly version: string | null;
  readonly findings: readonly Finding[];
  /** Failed lookups; they cost `onError` unless the package is allow-listed. */
  readonly errors: readonly DepwardError[];
}

/** The policy's verdict on one package. */
export interface PackageVerdict {
  readonly action: PolicyAction;
  /** In the order given, plus `denylisted` first when the deny list matched. */
  readonly findings: DecidedFinding[];
  /** `onError` when there were failed lookups that count, else `null`. */
  readonly errorAction: PolicyAction | null;
  readonly listed: ListMatch | null;
}

/** A compiled policy. Create one per config with {@link createPolicy}. */
export interface Policy {
  readonly config: DepwardConfig;
  /** The list entry matching the package; `deny` wins over `allow`. */
  listed(name: string, version: string | null): ListMatch | null;
  /** A deny entry that matches every version of `name`, so no lookup can change the outcome. */
  deniedByName(name: string): ListMatch | null;
  /** Actions for findings that belong to no package check (tokenizer findings). */
  decideFindings(findings: readonly Finding[]): DecidedFinding[];
  decidePackage(evidence: PackageEvidence): PackageVerdict;
}

const PAIRED = new Set(["low-downloads", "package-too-new"]);

const isHighDiff = (f: Finding): boolean => f.id.startsWith("diff-") && f.severity === "high";

/** What the escalations need to know about a package's findings as a whole. */
interface Facts {
  readonly present: ReadonlySet<string>;
  readonly highDiffs: number;
}

function facts(findings: readonly Finding[]): Facts {
  return { present: new Set(findings.map((f) => f.id)), highDiffs: findings.filter(isHighDiff).length };
}

/**
 * Compiles a config into a {@link Policy}.
 *
 * @throws DepwardError `INVALID_CONFIG` for a malformed `allow` or `deny` entry
 */
export function createPolicy(config: DepwardConfig = defaultConfig()): Policy {
  const allow: ListMatcher = compileList(config.allow, "allow");
  const deny: ListMatcher = compileList(config.deny, "deny");

  function decide(finding: Finding, { present, highDiffs }: Facts): DecidedFinding {
    let action = defaultAction(finding);
    let source: ActionSource = "default";
    const escalate =
      (PAIRED.has(finding.id) && present.has("low-downloads") && present.has("package-too-new")) ||
      (finding.id === "install-script" && (present.has("low-downloads") || present.has("package-too-new"))) ||
      (highDiffs >= 2 && isHighDiff(finding)) ||
      finding.severity === "critical";
    if (escalate && action !== "deny") {
      action = "deny";
      source = "escalation";
    }
    const override = Object.hasOwn(config.policy, finding.id) ? config.policy[finding.id] : undefined;
    if (override !== undefined) {
      action = override;
      source = "config";
    }
    return { finding, action, source };
  }

  const listed = (name: string, version: string | null): ListMatch | null => {
    const d = deny.match(name, version);
    if (d !== null) return { list: "deny", entry: d };
    const a = allow.match(name, version);
    return a === null ? null : { list: "allow", entry: a };
  };

  return {
    config,
    listed,

    deniedByName(name) {
      const d = deny.matchesName(name);
      return d === null ? null : { list: "deny", entry: d };
    },

    decideFindings(findings) {
      const known = facts(findings);
      return findings.map((f) => decide(f, known));
    },

    decidePackage({ name, version, findings, errors }) {
      const match = listed(name, version);
      const known = facts(findings);
      let decided = findings.map((f) => decide(f, known));

      if (match?.list === "allow") {
        decided = decided.map((d) => ({ ...d, action: "allow", source: "allow-list" }));
      } else if (match?.list === "deny") {
        decided = [{ finding: denylisted(name, version, match.entry, config.source), action: "deny", source: "deny-list" }, ...decided];
      }
      const errorAction = errors.length > 0 && match?.list !== "allow" ? config.onError : null;
      const action = strictest([...decided.map((d) => d.action), ...(errorAction === null ? [] : [errorAction])]);
      return { action, findings: decided, errorAction, listed: match };
    },
  };
}

function denylisted(name: string, version: string | null, entry: string, source: string | null): Finding {
  return {
    id: "denylisted",
    severity: "high",
    package: name,
    ...(version === null ? {} : { version }),
    message: `${name} is on the config's deny list (${JSON.stringify(entry)}).`,
    evidence: [{ detail: `deny entry ${JSON.stringify(entry)}${source === null ? "" : ` in ${source}`}` }],
    docsUrl: findingDocsUrl("denylisted"),
  };
}
