import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { TokenSavings } from "./TokenSavings";
import type { TokenSavings as TokenSavingsType } from "@/lib/types";

function makeSavings(overrides: Partial<TokenSavingsType> = {}): TokenSavingsType {
  return {
    context_tokens: 50,
    raw_tokens: 150,
    tokens_saved: 100,
    savings_pct: 67,
    prior_findings_used: 5,
    duplicates_removed: 10,
    ...overrides,
  };
}

describe("TokenSavings", () => {
  it("renders savings percentage and token count", () => {
    render(<TokenSavings savings={makeSavings()} />);
    expect(screen.getByText(/67%/)).toBeInTheDocument();
    expect(screen.getByText(/100/)).toBeInTheDocument();
  });

  it("shows prior findings count", () => {
    render(<TokenSavings savings={makeSavings()} />);
    expect(screen.getByText("results.priorFindings")).toBeInTheDocument();
  });

  it("shows duplicates removed count", () => {
    render(<TokenSavings savings={makeSavings()} />);
    expect(screen.getByText("results.duplicatesRemoved")).toBeInTheDocument();
  });

  it("renders nothing when tokens_saved is 0", () => {
    const { container } = render(<TokenSavings savings={makeSavings({ tokens_saved: 0 })} />);
    expect(container.firstChild).toBeNull();
  });

  it("hides prior findings when count is 0", () => {
    render(<TokenSavings savings={makeSavings({ prior_findings_used: 0 })} />);
    expect(screen.queryByText("results.priorFindings")).toBeNull();
  });

  it("hides duplicates removed when count is 0", () => {
    render(<TokenSavings savings={makeSavings({ duplicates_removed: 0 })} />);
    expect(screen.queryByText("results.duplicatesRemoved")).toBeNull();
  });

  it("has correct test id", () => {
    render(<TokenSavings savings={makeSavings()} />);
    expect(screen.getByTestId("token-savings")).toBeInTheDocument();
  });
});
