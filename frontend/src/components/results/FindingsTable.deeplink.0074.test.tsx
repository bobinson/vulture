import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// Feature 0074 (verification item 1b) — a `?finding=<id>` link, the ui_path the
// masked-values endpoint and the MCP tool hand out, must SHOW that finding even
// when it sits past the first page of the table, and also when the findings
// arrive after the first render (the page loads them asynchronously).
// The global test setup stubs `t` to echo the key.
import { FindingsTable } from "./FindingsTable";
import type { Finding } from "@/lib/types";

const FINDINGS: Finding[] = Array.from({ length: 60 }, (_, i) => ({
  id: `f${i}`,
  severity: "high",
  category: "CWE-798",
  title: `Finding ${String(i).padStart(2, "0")}`,
  description: `Description of finding ${i}`,
  file_path: `/src/file_${String(i).padStart(2, "0")}.ts`,
  recommendation: "fix",
  agent_type: "cwe",
}));

const linkTo = (id: string) => window.history.replaceState(null, "", `/audit/a1?finding=${id}`);

afterEach(() => window.history.replaceState(null, "", "/"));

describe("FindingsTable ?finding= deep link (0074 #1b)", () => {
  it("opens the page that holds the linked finding and expands it", () => {
    linkTo("f52");
    render(<FindingsTable findings={FINDINGS} />);
    expect(screen.getByText("Finding 52")).toBeInTheDocument();
    expect(screen.getByText("Description of finding 52")).toBeInTheDocument();
  });

  it("follows the link once the findings arrive after the first render", () => {
    linkTo("f41");
    const { rerender } = render(<FindingsTable findings={[]} />);
    rerender(<FindingsTable findings={FINDINGS} />);
    expect(screen.getByText("Description of finding 41")).toBeInTheDocument();
  });

  it("leaves the table on page one without a link", () => {
    render(<FindingsTable findings={FINDINGS} />);
    expect(screen.getByText("Finding 00")).toBeInTheDocument();
    expect(screen.queryByText("Finding 52")).not.toBeInTheDocument();
  });
});
