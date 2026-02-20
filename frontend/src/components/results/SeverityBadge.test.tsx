import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityBadge } from "./SeverityBadge";

describe("SeverityBadge", () => {
  it("renders severity text from i18n key", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("severity.critical")).toBeInTheDocument();
  });

  it("applies severity-critical class for critical", () => {
    const { container } = render(<SeverityBadge severity="critical" />);
    expect(container.querySelector(".severity-critical")).toBeInTheDocument();
  });

  it("applies severity-high class for high", () => {
    const { container } = render(<SeverityBadge severity="high" />);
    expect(container.querySelector(".severity-high")).toBeInTheDocument();
  });

  it("applies severity-info class for info", () => {
    const { container } = render(<SeverityBadge severity="info" />);
    expect(container.querySelector(".severity-info")).toBeInTheDocument();
  });

  it("renders as uppercase badge", () => {
    const { container } = render(<SeverityBadge severity="medium" />);
    expect(container.querySelector(".badge.uppercase")).toBeInTheDocument();
  });
});
