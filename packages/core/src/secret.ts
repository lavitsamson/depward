const REDACTED = "[redacted]";

/**
 * Wraps a credential so it cannot leak through logging, string interpolation,
 * `JSON.stringify`, or `util.inspect`. Call {@link Secret.reveal} only at the point
 * where the value goes into a request header.
 */
export class Secret {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  /** Returns the raw credential. Never pass the result to a logger. */
  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }
}

// util.inspect hook, defined outside the class body because computed method names
// can't be typed under `isolatedDeclarations`.
Object.defineProperty(Secret.prototype, Symbol.for("nodejs.util.inspect.custom"), {
  value: (): string => REDACTED,
});

/** Removes any `user:password@` part from a URL so it is safe to put in a message. */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.username || u.password) {
      u.username = "";
      u.password = "";
    }
    return u.href;
  } catch {
    return "<invalid url>";
  }
}
