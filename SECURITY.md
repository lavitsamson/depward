# Security policy

depward is a supply-chain security tool, so it is itself a target. Please report
vulnerabilities privately.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** ("Report a vulnerability" on the
Security tab of this repository). Please do not open a public issue.

Include the affected package and version, a description, and a minimal reproduction.
Do **not** attach live malware. A synthetic, inert sample that reproduces the pattern
is enough (see the fixture rules in `CLAUDE.md`).

We aim to acknowledge reports within 3 business days and to publish a fix and advisory
within 30 days of confirmation.

## In scope

- Ways to make depward execute code from an analyzed package.
- Tar extraction issues: path traversal, symlink escape, or writes outside the cache.
- Bypasses of the install gate (`allow` for something that should be `ask` or `deny`)
  that come from a bug rather than a documented limitation.
- Terminal or markdown injection through package metadata or contents.
- Leaking registry tokens to logs or output.

## Out of scope

- The documented limitations of `@depward/caps` runtime mode. It is defense in depth,
  **not a sandbox**.
- Packages whose malicious behavior is not visible to static analysis (for example,
  code fetched at runtime from a server that is benign during analysis). Reports that
  improve detection are still welcome as regular issues.

## Releases

Every release is published from CI with npm trusted publishing and carries a
provenance attestation. A depward release without provenance should be treated as
suspicious.
