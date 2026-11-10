import type { Packument, VersionMeta } from "@depward/core";
import { describe, expect, test } from "vitest";
import { publisherChange } from "../src/registry/history.ts";

interface V {
  v: string;
  at: string;
  by: string;
  maintainers?: string[];
}

function doc(versions: V[]): Packument {
  const out: Record<string, VersionMeta> = {};
  const time: Record<string, string> = {};
  for (const { v, at, by, maintainers } of versions) {
    out[v] = {
      name: "pkg",
      version: v,
      dist: { tarball: `https://registry.npmjs.org/pkg/-/pkg-${v}.tgz` },
      _npmUser: { name: by },
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
});
