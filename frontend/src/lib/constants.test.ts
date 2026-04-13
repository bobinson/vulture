import { describe, expect, it } from "vitest";
import { ROUTES, SEVERITY_COLORS, SEVERITY_ORDER, AGENT_TYPES, agentLabel } from "./constants";

describe("ROUTES", () => {
  it("defines dashboard at root", () => {
    expect(ROUTES.DASHBOARD).toBe("/");
  });

  it("generates audit result path", () => {
    expect(ROUTES.AUDIT_RESULTS("abc-123")).toBe("/audit/abc-123");
  });
});

describe("SEVERITY_COLORS", () => {
  it("maps all severity levels", () => {
    expect(SEVERITY_COLORS.critical).toBe("severity-critical");
    expect(SEVERITY_COLORS.high).toBe("severity-high");
    expect(SEVERITY_COLORS.medium).toBe("severity-medium");
    expect(SEVERITY_COLORS.low).toBe("severity-low");
    expect(SEVERITY_COLORS.info).toBe("severity-info");
  });
});

describe("SEVERITY_ORDER", () => {
  it("ranks critical highest", () => {
    expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
    expect(SEVERITY_ORDER.low).toBeLessThan(SEVERITY_ORDER.info);
  });
});

describe("AGENT_TYPES", () => {
  it("includes all agent types", () => {
    expect(AGENT_TYPES).toContain("chaos");
    expect(AGENT_TYPES).toContain("owasp");
    expect(AGENT_TYPES).toContain("soc2");
    expect(AGENT_TYPES).toContain("cwe");
    expect(AGENT_TYPES).toContain("xss");
    expect(AGENT_TYPES).toContain("ssdf");
  });
});

describe("agentLabel", () => {
  it("returns translated label when key exists", () => {
    const t = (key: string) => (key === "agents.chaos" ? "Chaos" : key);
    expect(agentLabel("chaos", t)).toBe("Chaos");
  });

  it("uppercases short types when no translation found", () => {
    const t = (key: string) => key; // returns key as-is (no translation)
    expect(agentLabel("ssdf", t)).toBe("SSDF");
    expect(agentLabel("gdpr", t)).toBe("GDPR");
    expect(agentLabel("cwe", t)).toBe("CWE");
    expect(agentLabel("soc2", t)).toBe("SOC2");
    expect(agentLabel("xss", t)).toBe("XSS");
  });

  it("capitalizes longer names when no translation found", () => {
    const t = (key: string) => key;
    expect(agentLabel("discover", t)).toBe("Discover");
  });
});
