# 0002 — Move the HTML-to-PDF product out of the depward repository

- Status: accepted
- Date: 2026-11-02

## Context

The roadmap planned an HTML-to-PDF renderer without Chromium as Phase 5, as a "separate
product, same monorepo". It shares nothing with depward except repo tooling: it does not
use `@depward/core`, findings, or the analyzer, and it has a different audience and
release cadence. Its leading architecture is a Rust core compiled to WASM, which would
bring Rust crates and a WASM build into this repository's CI.

depward is a supply-chain security tool and will be a target. Everything with write
access to this repository, and every build tool its CI runs, can influence depward
releases. Splitting is cheapest now, before any PDF code exists.

## Decision

- The PDF product lives in its own repository. It is no longer a depward phase.
- Its spec and the Phase 5 plan moved out of this repo (`docs/specs/pdf.md` is deleted)
  into a seed folder for the new repository.
- The depward roadmap ends at Phase 4.

## Consequences

- depward's CI and dependency graph stay JavaScript-only.
- The PDF repo must set up its own tooling and supply-chain hygiene, which duplicates
  some configuration.
- Nothing in depward may depend on the PDF product, and vice versa.
