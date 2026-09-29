import { groupByOwaspCategory, owaspLabels } from "./compliance.ts";
import type { Audit, Finding, ProveResult } from "./types.ts";

/** Escape text for use inside a markdown table cell. */
function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/`/g, "\\`").replace(/\n/g, " ");
}

export function findingToMarkdown(finding: Finding, auditId?: string): string {
  const sev = finding.severity.toUpperCase();
  const lines: string[] = [];

  lines.push(`## [${sev}] ${finding.title}`);
  lines.push("");

  // Metadata table
  lines.push("| Field | Value |");
  lines.push("|-------|-------|");
  lines.push(`| Severity | ${escapeCell(finding.severity)} |`);
  lines.push(`| Category | ${escapeCell(finding.category)} |`);

  // File with optional line range
  let fileRef = finding.file_path;
  if (finding.line_start) {
    fileRef += `:${finding.line_start}`;
    if (finding.line_end && finding.line_end !== finding.line_start) {
      fileRef += `-${finding.line_end}`;
    }
  }
  lines.push(`| File | \`${escapeCell(fileRef)}\` |`);

  const agent = finding.agent_type ?? finding.agent_id;
  if (agent) {
    lines.push(`| Agent | ${escapeCell(agent.toUpperCase())} |`);
  }

  if (auditId) {
    lines.push(`| Audit | ${escapeCell(auditId)} |`);
  }

  if (finding.compliance_ref) {
    lines.push(`| Compliance | ${escapeCell(finding.compliance_ref)} |`);
  }

  // Feature 0096: OWASP Top 10 categories the finding is labelled with.
  for (const l of owaspLabels(finding)) {
    lines.push(`| OWASP | ${escapeCell(`${l.category_id} ${l.category_name} (${l.edition})`)} |`);
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

export function proveResultToMarkdown(result: ProveResult, finding: Finding, auditId?: string): string {
  const sev = finding.severity.toUpperCase();
  const lines: string[] = [];

  lines.push(`## [${sev}] ${finding.title}`);
  lines.push("");

  // Metadata table
  lines.push("| Field | Value |");
  lines.push("|-------|-------|");
  lines.push(`| Severity | ${escapeCell(finding.severity)} |`);
  lines.push(`| Category | ${escapeCell(finding.category)} |`);

  let fileRef = finding.file_path;
  if (finding.line_start) {
    fileRef += `:${finding.line_start}`;
    if (finding.line_end && finding.line_end !== finding.line_start) {
      fileRef += `-${finding.line_end}`;
    }
  }
  lines.push(`| File | \`${escapeCell(fileRef)}\` |`);

  const agent = finding.agent_type ?? finding.agent_id;
  if (agent) {
    lines.push(`| Agent | ${escapeCell(agent.toUpperCase())} |`);
  }

  if (auditId) {
    lines.push(`| Audit | ${escapeCell(auditId)} |`);
  }

  if (finding.compliance_ref) {
    lines.push(`| Compliance | ${escapeCell(finding.compliance_ref)} |`);
  }

  // Prove-specific metadata
  lines.push(`| Verification | ${escapeCell(result.status)} |`);
  lines.push(`| Iterations | ${result.iterations_used} |`);
  if (result.staging_url) {
    lines.push(`| Staging URL | ${escapeCell(result.staging_url)} |`);
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

  // Reproduction Steps from evidence
  if (result.evidence) {
    lines.push("### Reproduction Steps");
    lines.push(result.evidence);
    lines.push("");
  }

  return lines.join("\n");
}

export function auditReportToMarkdown(audit: Audit, findings: Finding[], sourcePath?: string): string {
  const lines: string[] = [];

  lines.push("# Vulture Audit Report");
  lines.push("");
  lines.push(`**Audit ID:** ${audit.id}`);
  if (sourcePath) {
    lines.push(`**Source:** ${sourcePath}`);
  }
  lines.push(`**Status:** ${audit.status}`);
  lines.push(`**Date:** ${new Date(audit.created_at).toLocaleString()}`);
  if (audit.types?.length) {
    lines.push(`**Agents:** ${audit.types.join(", ")}`);
  }
  lines.push(`**Findings:** ${findings.length}`);
  lines.push("");
  lines.push("---");
  lines.push("");

  const owasp = owaspSectionMarkdown(findings);
  if (owasp) {
    lines.push(owasp);
    lines.push("---");
    lines.push("");
  }

  lines.push(findings.map((f) => findingToMarkdown(f, audit.id)).join("\n---\n\n"));

  return lines.join("\n");
}

function fileRefOf(finding: Finding): string {
  return finding.line_start ? `${finding.file_path}:${finding.line_start}` : finding.file_path;
}

/**
 * Feature 0096: the report's OWASP Top 10 section — one heading per edition,
 * one sub-heading per category, the labelled findings under each. Computed
 * from the findings' labels, so a finding is listed under every category it
 * maps to but counted once in the report. Empty when nothing is labelled.
 */
function owaspSectionMarkdown(findings: Finding[]): string {
  const groups = groupByOwaspCategory(findings);
  const lines: string[] = [];
  let edition = "";
  for (const g of groups) {
    if (g.edition !== edition) {
      edition = g.edition;
      lines.push(`## OWASP Top 10:${edition}`);
      lines.push("");
    }
    lines.push(`### ${g.id} ${g.name} (${g.findings.length})`);
    lines.push("");
    for (const f of g.findings) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.title} — \`${fileRefOf(f)}\``);
    }
    lines.push("");
  }
  return lines.join("\n");
}
