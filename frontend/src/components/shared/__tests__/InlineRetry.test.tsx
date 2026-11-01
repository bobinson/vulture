import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { InlineRetry } from "../InlineRetry";
import { watchAnnouncements } from "@/test/liveRegion";

// Shared compact failure state: error text plus a retry button. The test i18n
// mock renders keys, so the retry label is its key.

describe("InlineRetry (shared)", () => {
  it("announces the message as an alert with a retry button inside", () => {
    render(<InlineRetry message="Something failed" onRetry={vi.fn()} />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Something failed common.retry");
    expect(screen.getByText("Something failed")).toBe(alert);
    expect(screen.getByRole("button", { name: "common.retry" })).toHaveAttribute("type", "button");
  });

  it("calls onRetry once per click", () => {
    const onRetry = vi.fn();
    render(<InlineRetry message="Something failed" onRetry={onRetry} />);
    fireEvent.click(screen.getByRole("button", { name: "common.retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  // Busy: the retried action is in flight. The button stays enabled for focus
  // (a focused control must not be torn away), so aria carries the state and
  // a press is not passed on.
  it("marks the retry busy and disabled, keeps it focusable and ignores a press while busy", () => {
    const onRetry = vi.fn();
    render(<InlineRetry message="Something failed" onRetry={onRetry} busy />);
    const retry = screen.getByRole("button", { name: "common.retry" });

    expect(retry).toHaveAttribute("aria-busy", "true");
    expect(retry).toHaveAttribute("aria-disabled", "true");
    expect(retry).not.toBeDisabled();
    retry.focus();
    fireEvent.click(retry);

    expect(document.activeElement).toBe(retry);
    expect(onRetry).not.toHaveBeenCalled();
  });

  it("is neither busy nor disabled by default", () => {
    render(<InlineRetry message="Something failed" onRetry={vi.fn()} />);
    const retry = screen.getByRole("button", { name: "common.retry" });

    expect(retry).not.toHaveAttribute("aria-busy", "true");
    expect(retry).not.toHaveAttribute("aria-disabled", "true");
  });

  // A repeat failure leaves the same message, so unless the alert's content
  // changes, a screen reader says nothing (WCAG 4.1.3). A new failure count
  // re-adds the message to the alert; the retry button is the same node and
  // keeps the focus.
  it("re-announces the message for a new failure count and keeps the retry button and its focus", () => {
    const { rerender } = render(<InlineRetry message="Something failed" onRetry={vi.fn()} failureCount={1} />);
    const alert = screen.getByRole("alert");
    const retry = screen.getByRole("button", { name: "common.retry" });
    retry.focus();
    const announced = watchAnnouncements(alert);

    rerender(<InlineRetry message="Something failed" onRetry={vi.fn()} failureCount={2} />);

    expect(announced()).toEqual(["Something failed"]);
    expect(alert).toHaveTextContent("Something failed common.retry");
    expect(screen.getByRole("button", { name: "common.retry" })).toBe(retry);
    expect(document.activeElement).toBe(retry);
  });

  it("does not re-announce while the failure count is unchanged", () => {
    const { rerender } = render(<InlineRetry message="Something failed" onRetry={vi.fn()} failureCount={1} />);
    const announced = watchAnnouncements(screen.getByRole("alert"));

    rerender(<InlineRetry message="Something failed" onRetry={vi.fn()} failureCount={1} busy />);
    rerender(<InlineRetry message="Something failed" onRetry={vi.fn()} failureCount={1} />);

    expect(announced()).toEqual([]);
  });
});
