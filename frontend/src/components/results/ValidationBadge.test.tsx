import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { ValidationBadge } from "./ValidationBadge";

// i18n: render the raw key so tests don't depend on locale strings.
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}));
import { vi } from "vitest";

describe("ValidationBadge", () => {
  it("renders a badge for likely_fp", () => {
    const { container } = render(<ValidationBadge status="likely_fp" />);
    expect(container.textContent).toContain("results.validation.likely_fp");
  });

  it("renders a badge for suspicious", () => {
    const { container } = render(<ValidationBadge status="suspicious" />);
    expect(container.textContent).toContain("results.validation.suspicious");
  });

  it("renders nothing for high_confidence (default-trust state, no noise)", () => {
    const { container } = render(<ValidationBadge status="high_confidence" />);
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing for empty/undefined status (pre-0045 findings)", () => {
    const { container: c1 } = render(<ValidationBadge status="" />);
    expect(c1.firstChild).toBeNull();
    const { container: c2 } = render(<ValidationBadge status={undefined} />);
    expect(c2.firstChild).toBeNull();
  });

  it("renders nothing for an unknown status value", () => {
    const { container } = render(<ValidationBadge status="garbage" />);
    expect(container.firstChild).toBeNull();
  });
});
