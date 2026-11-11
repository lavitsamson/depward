import type { Packument, VersionMeta } from "@depward/core";
import { describe, expect, test } from "vitest";
import { provenanceDrop, publisherChange } from "../src/registry/history.ts";

interface V {
  v: string;
  at: string;
  by: string;
  maintainers?: string[];
  attest?: boolean;
  /** Published through npm trusted publishing (OIDC): `_npmUser.trustedPublisher`, plus SLSA provenance. */
  trusted?: boolean;
}

function doc(versions: V[]): Packument {
  const out: Record<string, VersionMeta> = {};
  const time: Record<string, string> = {};
  for (const { v, at, by, maintainers, attest, trusted } of versions) {
    out[v] = {
      name: "pkg",
      version: v,
      dist: {
        tarball: `https://registry.npmjs.org/pkg/-/pkg-${v}.tgz`,
        ...(attest || trusted ? { attestations: { url: `https://registry.npmjs.org/-/npm/v1/attestations/pkg@${v}`, ...(trusted ? { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } : {}) } } : {}),
      },
      _npmUser: trusted ? { name: by, email: "npm-oidc-no-reply@github.com", trustedPublisher: { id: "github", oidcConfigId: "00000000-0000-4000-8000-000000000000" } } : { name: by },
      ...(maintainers ? { maintainers: maintainers.map((name) => ({ name })) } : {}),
    };
    time[v] = at;
  }
  return { name: "pkg", "dist-tags": {}, versions: out, time };
}

const check = (p: Packument, v: string) => publisherChange(p, p.versions[v] as VersionMeta);

/** carol is first listed on a release published at `since`, then publishes 1.0.2 on 2024-03-01. */
function carolListedSince(since: string): Packument {
  return doc([
    { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice", maintainers: ["alice"] },
    { v: "1.0.1", at: since, by: "alice", maintainers: ["alice", "carol"] },
    { v: "1.0.2", at: "2024-03-01T00:00:00Z", by: "carol", maintainers: ["alice", "carol"] },
  ]);
}

describe("publisherChange", () => {
  test("a publisher of a recent version is known", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "alice" },
    ]);
    expect(check(p, "1.0.1")).toBeNull();
  });

  test("a new account is flagged, with the earlier publishers", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice", maintainers: ["alice"] },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "bob", maintainers: ["alice", "bob"] },
      { v: "1.0.2", at: "2024-03-01T00:00:00Z", by: "mallory", maintainers: ["alice", "bob", "mallory"] },
    ]);
    expect(check(p, "1.0.2")).toEqual({ publisher: "mallory", previous: ["bob", "alice"] });
  });

  test("an existing maintainer publishing for the first time is not flagged", () => {
    // typescript@7.0.2-style: the CI account was listed long before it published.
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "bot", maintainers: ["bot", "ci"] },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "bot", maintainers: ["bot", "ci"] },
      { v: "1.1.0", at: "2024-03-01T00:00:00Z", by: "ci", maintainers: ["bot", "ci"] },
    ]);
    expect(check(p, "1.1.0")).toBeNull();
  });

  test("only the version just before counts for the maintainers rule", () => {
    // Listed long ago, then removed, now back to publish: still flagged.
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice", maintainers: ["alice", "eve"] },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "alice", maintainers: ["alice"] },
      { v: "1.0.2", at: "2024-03-01T00:00:00Z", by: "eve", maintainers: ["alice", "eve"] },
    ]);
    expect(check(p, "1.0.2")?.publisher).toBe("eve");
  });

  test("an account added in a recent release is still flagged", () => {
    // A compromised account first ships a release that lists mallory, then mallory
    // publishes. mallory isn't established (not listed 30+ days before), so it's flagged.
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice", maintainers: ["alice"] },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "alice", maintainers: ["alice", "mallory"] },
      { v: "1.0.2", at: "2024-02-02T00:00:00Z", by: "mallory", maintainers: ["alice", "mallory"] },
    ]);
    expect(check(p, "1.0.2")).toEqual({ publisher: "mallory", previous: ["alice"] });
  });

  test("established means listed at least 30 days before the publish", () => {
    expect(check(carolListedSince("2024-01-31T00:00:00Z"), "1.0.2")).toBeNull(); // 30 days before
    expect(check(carolListedSince("2024-02-01T00:00:00Z"), "1.0.2")?.publisher).toBe("carol"); // 29 days
  });

  test("no history or no publisher: nothing to compare", () => {
    const p = doc([{ v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" }]);
    expect(check(p, "1.0.0")).toBeNull();
    const anon = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "" },
    ]);
    expect(check(anon, "1.0.1")).toBeNull();
  });

  // Approved 2026-11-11 after the top-1,000 benchmark (docs/benchmarks.md).
  test("moving to trusted publishing with provenance is not a publisher change", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "GitHub Actions", trusted: true },
    ]);
    expect(check(p, "1.0.1")).toBeNull();
  });

  test("a trusted-publisher identity without provenance is still flagged", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "GitHub Actions", trusted: true },
    ]);
    const meta = p.versions["1.0.1"] as VersionMeta;
    const noProvenance = { ...meta, dist: { ...meta.dist, attestations: { url: "https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.1" } } };
    expect(publisherChange(p, noProvenance)?.publisher).toBe("GitHub Actions");
    // A name alone proves nothing: _npmUser without trustedPublisher is an ordinary account.
    const lookalike = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "GitHub Actions", attest: true },
    ]);
    expect(check(lookalike, "1.0.1")?.publisher).toBe("GitHub Actions");
  });

  test("a person publishing after trusted-publishing releases is still checked", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "GitHub Actions", trusted: true },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "GitHub Actions", trusted: true },
      { v: "1.0.2", at: "2024-03-01T00:00:00Z", by: "mallory" },
    ]);
    expect(check(p, "1.0.2")).toEqual({ publisher: "mallory", previous: ["GitHub Actions"] });
  });

  test("a change more than 90 days ago is history, not a takeover in progress", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "alice" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "mallory" },
    ]);
    const meta = p.versions["1.0.1"] as VersionMeta;
    const at = Date.parse("2024-02-01T00:00:00Z");
    const day = 86_400_000;
    expect(publisherChange(p, meta, { now: at + 90 * day })?.publisher).toBe("mallory");
    expect(publisherChange(p, meta, { now: at + 90 * day + 1 })).toBeNull();
    expect(publisherChange(p, meta)?.publisher).toBe("mallory"); // no clock: no age limit
  });
});

const drop = (p: Packument, v: string) => provenanceDrop(p, p.versions[v] as VersionMeta)?.version ?? null;

describe("provenanceDrop", () => {

  test("a stable release after attested stable releases", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "a", attest: true },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "a" },
    ]);
    expect(drop(p, "1.0.1")).toBe("1.0.0");
  });

  test("a stable line that never had provenance, next to attested prereleases (rxjs@7.8.2)", () => {
    const p = doc([
      { v: "7.8.1", at: "2023-04-01T00:00:00Z", by: "a" },
      { v: "8.0.0-alpha.13", at: "2023-12-20T00:00:00Z", by: "a", attest: true },
      { v: "8.0.0-alpha.14", at: "2024-01-12T00:00:00Z", by: "a", attest: true },
      { v: "7.8.2", at: "2025-02-22T00:00:00Z", by: "a" },
    ]);
    expect(drop(p, "7.8.2")).toBeNull();
  });

  test("a stable release that drops provenance is caught across interleaved prereleases", () => {
    const p = doc([
      { v: "2.0.0", at: "2024-01-01T00:00:00Z", by: "a", attest: true },
      { v: "3.0.0-beta.1", at: "2024-02-01T00:00:00Z", by: "a" },
      { v: "3.0.0-beta.2", at: "2024-03-01T00:00:00Z", by: "a" },
      { v: "2.0.1", at: "2024-04-01T00:00:00Z", by: "a" },
    ]);
    expect(drop(p, "2.0.1")).toBe("2.0.0");
  });

  test("a prerelease is compared with every earlier version", () => {
    const fromStable = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "a", attest: true },
      { v: "1.1.0-rc.1", at: "2024-02-01T00:00:00Z", by: "a" },
    ]);
    expect(drop(fromStable, "1.1.0-rc.1")).toBe("1.0.0");
    const fromPre = doc([
      { v: "1.1.0-rc.1", at: "2024-01-01T00:00:00Z", by: "a", attest: true },
      { v: "1.1.0-rc.2", at: "2024-02-01T00:00:00Z", by: "a" },
    ]);
    expect(drop(fromPre, "1.1.0-rc.2")).toBe("1.1.0-rc.1");
  });

  test("an attested version, or one with no attested history, is not a drop", () => {
    const p = doc([
      { v: "1.0.0", at: "2024-01-01T00:00:00Z", by: "a" },
      { v: "1.0.1", at: "2024-02-01T00:00:00Z", by: "a", attest: true },
    ]);
    expect(drop(p, "1.0.0")).toBeNull();
    expect(drop(p, "1.0.1")).toBeNull();
  });
});
