import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreCard } from "./ScoreCard";

describe("ScoreCard", () => {
  it("renders score value", () => {
    render(<ScoreCard label="OWASP" score={75} />);
    expect(screen.getByText("75")).toBeInTheDocument();
  });

  it("renders label", () => {
    render(<ScoreCard label="Chaos" score={90} />);
    expect(screen.getByText("Chaos")).toBeInTheDocument();
  });

  it("rounds score to integer", () => {
    render(<ScoreCard label="Test" score={72.6} />);
    expect(screen.getByText("73")).toBeInTheDocument();
  });

  it("uses success color for high scores (>=80)", () => {
    const { container } = render(<ScoreCard label="Test" score={85} />);
    expect(container.querySelector(".text-success")).toBeInTheDocument();
  });

  it("uses warning color for medium scores (50-79)", () => {
    const { container } = render(<ScoreCard label="Test" score={65} />);
    expect(container.querySelector(".text-warning")).toBeInTheDocument();
  });

  it("uses danger color for low scores (<50)", () => {
    const { container } = render(<ScoreCard label="Test" score={30} />);
    expect(container.querySelector(".text-danger")).toBeInTheDocument();
  });

  it("renders SVG circle for gauge", () => {
    const { container } = render(<ScoreCard label="Test" score={50} />);
    const circles = container.querySelectorAll("circle");
    expect(circles.length).toBe(2); // background + progress
  });

  it("renders green stroke for score >= 80", () => {
    const { container } = render(<ScoreCard label="Test" score={90} />);
    const circles = container.querySelectorAll("circle");
    expect(circles[1].getAttribute("stroke")).toBe("#2DA44E");
  });

  it("renders yellow stroke for score 50-79", () => {
    const { container } = render(<ScoreCard label="Test" score={60} />);
    const circles = container.querySelectorAll("circle");
    expect(circles[1].getAttribute("stroke")).toBe("#BF8700");
  });

  it("renders red stroke for score < 50", () => {
    const { container } = render(<ScoreCard label="Test" score={25} />);
    const circles = container.querySelectorAll("circle");
    expect(circles[1].getAttribute("stroke")).toBe("#CF222E");
  });
});
