import { memo } from "react";
import { useTranslation } from "react-i18next";
import type { LineageStatus } from "@/lib/types.ts";

/**
 * Status colours are SEMANTIC and deliberately drawn from outside the product
 * accent (#2563eb): the accent means "this is interactive", and a status is
 * not a control. Each of the eight statuses gets its own pair so no two read
 * as the same thing at a glance.
 *
 *   open            neutral  — known, nobody has moved on it
 *   in_progress     blue     — someone is on it
 *   unconfirmed     orange   — the scanner could NOT re-read the evidence, so
 *                              this is neither "still there" nor "gone"; it is
 *                              the one status that asks a human to look
 *   regression      red      — closed once, back again
 *   fixed           green    — the scan proved the evidence gone
 *   resolved        emerald  — a human closed it
 *   accepted_risk   amber    — knowingly kept
 *   false_positive  purple   — rejected
 */
const STATUS_COLORS: Record<LineageStatus, string> = {
  open: "bg-[#E5E7EB] text-[#374151]",
  in_progress: "bg-[#DBEAFE] text-[#1E40AF]",
  unconfirmed: "bg-[#FFEDD5] text-[#9A3412] ring-1 ring-inset ring-[#FDBA74]",
  resolved: "bg-[#D1FAE5] text-[#065F46]",
  accepted_risk: "bg-[#FEF3C7] text-[#92400E]",
  false_positive: "bg-[#F3E8FF] text-[#6B21A8]",
  fixed: "bg-[#DCFCE7] text-[#166534]",
  regression: "bg-[#FEE2E2] text-[#991B1B]",
};

interface Props {
  status: LineageStatus;
}

// memo'd: the aggregate table renders one per row, and a filter change
// re-renders the whole page while almost every status stays put.
//
// Every chip carries its own plain-English explanation, because a status word
// on its own is not self-describing — "Could not confirm" in particular means
// "the scan could not re-find this, but the code it cites has not changed",
// which no two-word label can say. The explanation is both the hover title and
// the accessible name, so it reaches a mouse, a keyboard and a screen reader.
function LineageStatusBadgeImpl({ status }: Props) {
  const { t } = useTranslation();
  const label = t(`lineage.status_${status}`);
  const hint = t(`lineage.statusHint_${status}`, { defaultValue: "" });
  return (
    <span
      data-testid={`lineage-status-${status}`}
      title={hint || label}
      aria-label={hint ? `${label} — ${hint}` : label}
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_COLORS[status] ?? STATUS_COLORS.open}`}
    >
      {label}
    </span>
  );
}

export const LineageStatusBadge = memo(LineageStatusBadgeImpl);
