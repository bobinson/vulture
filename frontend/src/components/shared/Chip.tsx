import { memo } from "react";

// Feature 0058 — shared, reusable pill component.
//
// Visual language matches the `badge` utility (index.css) used by
// SeverityBadge & co: same padding / radius / font-size tokens, so a
// Chip sits pixel-identically next to the existing badges. Tone colors
// reuse the palette already established by STATUS_STYLES / severity-*
// utilities; `active` reuses the filter-button selected state
// (bg-foreground text-surface).
//
// memo'd: rendered per finding row and per filter option; parent
// re-renders (filter / sort / expand) shouldn't reconcile every chip.

export type ChipTone = "neutral" | "info" | "success" | "warning" | "danger";

interface ChipProps {
  label: string;
  tone?: ChipTone;
  title?: string;
  onClick?: () => void;
  active?: boolean;
  /** data-testid override; defaults to "chip". */
  testId?: string;
}

const TONE_CLASSES: Record<ChipTone, string> = {
  neutral: "bg-cream text-muted",
  info: "bg-[#DBEAFE] text-[#1E40AF]",
  success: "bg-[#DCFCE7] text-[#166534]",
  warning: "bg-[#FEF3C7] text-[#92400E]",
  danger: "bg-[#FEE2E2] text-[#991B1B]",
};

function ChipImpl({ label, tone = "neutral", title, onClick, active = false, testId = "chip" }: ChipProps) {
  const toneClass = active ? "bg-foreground text-surface" : TONE_CLASSES[tone];
  const dataAttrs = {
    "data-testid": testId,
    "data-tone": tone,
    "data-active": active ? "true" : undefined,
  };

  if (!onClick) {
    return (
      <span className={`badge ${toneClass}`} title={title} {...dataAttrs}>
        {label}
      </span>
    );
  }

  return (
    <button
      type="button"
      className={`badge ${toneClass} transition-colors cursor-pointer ${active ? "" : "hover:text-foreground hover:bg-cream-dark"}`}
      title={title}
      aria-pressed={active}
      onClick={onClick}
      {...dataAttrs}
    >
      {label}
    </button>
  );
}

export const Chip = memo(ChipImpl);
