import { describe, expect, it } from "vitest";
import { auditReportToMarkdown, findingToMarkdown } from "./markdown.ts";
import type { Audit, ComplianceLabel, Finding } from "./types.ts";

// Feature 0096: the exported report carries an OWASP section grouped by
// category, computed from each finding's compliance labels.

const A07: ComplianceLabel = {
  framework: "owasp", edition: "2025", category_id: "A07",
  category_name: "Authentication Failures", cwe: "CWE-798",
};
const A05: ComplianceLabel = {
  framework: "owasp", edition: "2025", category_id: "A05", category_name: "Injection", cwe: "CWE-89",
};

function f(over: Partial<Finding>): Finding {
  return {
    severity: "high", category: "CWE-798", title: "t", description: "d",
    file_path: "a.ts", recommendation: "r", agent_type: "cwe", ...over,
  };
}

const AUDIT: Audit = {
  id: "audit-1", source_id: "s", status: "completed", types: ["cwe", "owasp"],
  created_at: "2026-09-29T00:00:00Z",
} as Audit;

describe("auditReportToMarkdown OWASP section", () => {
  const findings = [
    f({ title: "Env secret", severity: "low", file_path: ".env", line_start: 2, compliance_labels: [A07] }),
    f({ title: "SQLi", severity: "critical", category: "CWE-89", file_path: "db.go", compliance_labels: [A05] }),
    f({ title: "Cred", file_path: "cfg.ts", line_start: 9, compliance_labels: [A07] }),
    f({ title: "ReDoS", category: "CWE-1333" }),
  ];
  const md = auditReportToMarkdown(AUDIT, findings);
  const section = md.slice(md.indexOf("## OWASP Top 10:2025"), md.indexOf("\n---", md.indexOf("## OWASP")));

  it("has one heading per edition and one sub-heading per category, in id order", () => {
    expect(md).toContain("## OWASP Top 10:2025");
    expect(section.indexOf("### A05 Injection (1)")).toBeGreaterThan(-1);
    expect(section.indexOf("### A07 Authentication Failures (2)")).toBeGreaterThan(section.indexOf("### A05"));
  });

  it("lists each labelled finding under its category, worst first, with its location", () => {
    const a07 = section.slice(section.indexOf("### A07"));
    expect(a07.indexOf("[HIGH] Cred")).toBeLessThan(a07.indexOf("[LOW] Env secret"));
    expect(a07).toContain("`cfg.ts:9`");
    expect(section).not.toContain("ReDoS");
    // …while the full finding list below still carries every finding.
    expect(md).toContain("## [HIGH] ReDoS");
  });

  it("omits the section when no finding carries an OWASP label", () => {
    expect(auditReportToMarkdown(AUDIT, [f({ title: "x" })])).not.toContain("OWASP Top 10");
  });
});

describe("findingToMarkdown", () => {
  it("names each OWASP label in the metadata table", () => {
    expect(findingToMarkdown(f({ compliance_labels: [A07] }))).toContain(
      "| OWASP | A07 Authentication Failures (2025) |",
    );
    expect(findingToMarkdown(f({}))).not.toContain("| OWASP |");
  });
});
