import { describe, it, expect } from "vitest";
import { isBanking, classify, run, demo, inspect } from "../src/engine";

describe("session-firewall", () => {
  it("detects banking hosts", () => {
    expect(isBanking("https://pay.stripe.com/x")).toBe(true);
    expect(isBanking("https://example.com")).toBe(false);
  });
  it("blocks banking writes", () => {
    const r = classify({ method: "POST", url: "https://bank.example/x" }, "banking");
    expect(r.action).toBe("block");
  });
  it("scrubs cookies", () => {
    const r = classify({ method: "GET", url: "https://bank.example/", headers: { Cookie: "a=1" } }, "banking");
    expect(r.action).toBe("scrub");
    expect(r.scrubbedHeaders).toContain("cookie");
  });
  it("demo + inspect", () => {
    expect(demo().metrics.blocked).toBeGreaterThan(0);
    expect(inspect().features).toContain("banking-mode");
    expect(run({}).author).toContain("zAx4hub");
  });
});
