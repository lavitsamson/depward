/** Machine-readable error codes. Extend this union as new failure modes are added. */
export type DepwardErrorCode =
  | "INTERNAL"
  | "INVALID_ARGUMENT"
  | "NETWORK"
  | "TIMEOUT"
  | "INTEGRITY_MISMATCH"
  | "LIMIT_EXCEEDED";

/** The only error type depward throws. Callers branch on `code`, never on `message`. */
export class DepwardError extends Error {
  override readonly name: string = "DepwardError";
  readonly code: DepwardErrorCode;

  constructor(code: DepwardErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
  }
}

/** Type guard for {@link DepwardError}, optionally checking for a specific code. */
export function isDepwardError(value: unknown, code?: DepwardErrorCode): value is DepwardError {
  return value instanceof DepwardError && (code === undefined || value.code === code);
}
