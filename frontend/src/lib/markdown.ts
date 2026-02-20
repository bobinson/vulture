import type { Finding } from "./types.ts";

export function findingToMarkdown(finding: Finding, auditId?: string): string {
  const sev = finding.severity.toUpperCase();
  const lines: string[] = [];

  lines.push(`## [${sev}] ${finding.title}`);
  lines.push("");

  // Metadata table
  lines.push("| Field | Value |");
  lines.push("|-------|-------|");
  lines.push(`| Severity | ${finding.severity} |`);
  lines.push(`| Category | ${finding.category} |`);

  // File with optional line range
  let fileRef = finding.file_path;
  if (finding.line_start) {
    fileRef += `:${finding.line_start}`;
    if (finding.line_end && finding.line_end !== finding.line_start) {
      fileRef += `-${finding.line_end}`;
    }
  }
  lines.push(`| File | \`${fileRef}\` |`);

  const agent = finding.agent_type ?? finding.agent_id;
  if (agent) {
    lines.push(`| Agent | ${agent.toUpperCase()} |`);
  }

  if (auditId) {
    lines.push(`| Audit | ${auditId} |`);
  }

  if (finding.compliance_ref) {
    lines.push(`| Compliance | ${finding.compliance_ref} |`);
  }

  lines.push("");

  // Description
  lines.push("### Description");
  lines.push(finding.description);
  lines.push("");

  // Code snippet (optional)
  if (finding.code_snippet) {
    lines.push("### Code");
    lines.push("```");
    lines.push(finding.code_snippet);
    lines.push("```");
    lines.push("");
  }

  // Recommendation
  lines.push("### Recommendation");
  lines.push(finding.recommendation);
  lines.push("");

  return lines.join("\n");
}
