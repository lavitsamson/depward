// Default action per finding ID. Spec: docs/specs/gate.md §Policy engine; the actions
// are listed per ID in docs/findings.md.

import type { Finding, PolicyAction, Severity } from "@depward/core";

const RANK: Readonly<Record<PolicyAction, number>> = { allow: 0, ask: 1, deny: 2 };

/** The more severe of two actions (`deny` > `ask` > `allow`). */
export function stricter(a: PolicyAction, b: PolicyAction): PolicyAction {
  return RANK[b] > RANK[a] ? b : a;
}

/** The most severe action in `actions`, or `allow` when there are none. */
export function strictest(actions: Iterable<PolicyAction>): PolicyAction {
  let result: PolicyAction = "allow";
  for (const a of actions) result = stricter(result, a);
  return result;
}

/**
 * Default actions for every finding ID depward emits. Registry, command, and archive
 * findings follow the gate spec's tables. Analyzer signals follow their severity
 * (critical → deny, high → ask, lower → allow), except `env-sensitive-read`: reading a
 * token-like variable alone is common in benign code, and the token-stealer shape
 * (read flowing into a network call) is `env-exfil-pattern`, which denies. Update-diff
 * findings ask when something new appears that the locked version didn't have, except
 * new endpoints and dependencies (common in normal releases; a raw-IP endpoint is
 * `high` and counts toward the two-highs escalation) and the semver mismatch.
 */
export const DEFAULT_ACTIONS: Readonly<Record<string, PolicyAction>> = {
  // Command (tokenizer)
  "non-registry-source": "ask",
  "unparseable-command": "ask",
  "global-install": "allow",
  // Registry
  "package-not-found": "deny",
  "known-hallucinated-name": "deny",
  "version-not-found": "deny",
  "version-too-new": "ask",
  "package-too-new": "ask",
  "low-downloads": "ask",
  "typosquat-suspect": "ask",
  "publisher-changed": "ask",
  "maintainer-added-recently": "allow",
  "provenance-dropped": "ask",
  deprecated: "allow",
  // Archive
  "tarball-integrity-mismatch": "deny",
  "tarball-unsafe": "deny",
  // Lockfile (emitted by @depward/diff lockfile mode)
  "lockfile-integrity-mismatch": "deny",
  // Analyzer signals
  "install-script": "allow",
  "install-script-network": "ask",
  "env-sensitive-read": "allow",
  "env-exfil-pattern": "deny",
  "fs-sensitive-path": "ask",
  obfuscation: "ask",
  "encoded-payload": "ask",
  "high-entropy-string": "allow",
  "hardcoded-endpoint": "allow",
  "raw-ip-endpoint": "allow",
  "native-binary": "allow",
  "unparseable-file": "allow",
  "oversized-file": "allow",
  "minified-only": "allow",
  // Update diff (emitted by @depward/diff; reaches the gate through the update path)
  "diff-new-install-script": "ask",
  "diff-new-capability": "ask",
  "diff-new-network-in-non-network-pkg": "ask",
  "diff-new-sensitive-env": "ask",
  "diff-new-endpoint": "allow",
  "diff-new-obfuscation": "deny",
  "diff-new-dependency": "allow",
  "diff-publisher-changed": "ask",
  // Capability lockfile (emitted by @depward/caps; the gate never emits it, but config
  // overrides of it go through this table)
  "caps-unapproved": "ask",
  "diff-provenance-dropped": "ask",
  "diff-semver-mismatch": "allow",
  // Policy
  denylisted: "deny",
};

const BY_SEVERITY: Readonly<Record<Severity, PolicyAction>> = {
  critical: "deny", high: "ask", medium: "allow", low: "allow", info: "allow",
};

/** The default action for a finding: its ID's entry in {@link DEFAULT_ACTIONS}, else by severity. */
export function defaultAction(finding: Finding): PolicyAction {
  return Object.hasOwn(DEFAULT_ACTIONS, finding.id) ? (DEFAULT_ACTIONS[finding.id] as PolicyAction) : BY_SEVERITY[finding.severity];
}
