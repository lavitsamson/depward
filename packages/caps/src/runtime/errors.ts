// The error of the runtime layer's enforce mode (docs/specs/caps.md § Enforce details).
// The runtime can't import @depward/core, so this mirrors DepwardError's shape: a typed
// `code` on an Error subclass.

/** Codes of {@link DepwardCapabilityError}. */
export type CapabilityErrorCode =
  /** A package used a capability its entry in capabilities.lock.json doesn't list. */
  | "CAPS_DENIED"
  /** Enforce mode could not load the capability lockfile (thrown at startup). */
  | "CAPS_POLICY";

/** Details of a denied use. */
export interface DeniedUse {
  /** `name@version`. */
  package: string;
  capability: string;
  /** What was called, for example `fs.readFileSync`. */
  member: string;
  /** `file:line:column` of the package code that made the call, when known. */
  callSite: string | null;
}

// Package names and paths come from untrusted packages: strip control characters so the
// message can't carry terminal escape sequences.
const clean = (s: string): string =>
  [...s]
    .filter((ch) => {
      const c = ch.codePointAt(0) ?? 0;
      return c >= 0x20 && (c < 0x7f || c > 0x9f);
    })
    .join("");

/** Thrown in enforce mode for an unapproved capability use, or when the policy can't load. */
export class DepwardCapabilityError extends Error {
  override readonly name: string = "DepwardCapabilityError";
  readonly code: CapabilityErrorCode;
  /** Set for `CAPS_DENIED`. */
  readonly denied: DeniedUse | null;

  constructor(code: CapabilityErrorCode, message: string, denied: DeniedUse | null = null) {
    super(clean(message));
    this.code = code;
    this.denied = denied;
  }

  /** The error for a denied use, with an approval hint. */
  static denied(use: DeniedUse): DepwardCapabilityError {
    const at = use.callSite === null ? "" : ` at ${use.callSite}`;
    const name = use.package.slice(0, use.package.lastIndexOf("@") > 0 ? use.package.lastIndexOf("@") : use.package.length);
    return new DepwardCapabilityError(
      "CAPS_DENIED",
      `package ${use.package} used capability "${use.capability}" (${use.member})${at}, which capabilities.lock.json does not approve. ` +
        `If it is expected: depward caps approve ${name} --cap ${use.capability} --reason "..."`,
      use,
    );
  }
}
