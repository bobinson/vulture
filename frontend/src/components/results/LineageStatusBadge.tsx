import { useTranslation } from "react-i18next";
import type { LineageStatus } from "@/lib/types.ts";

const STATUS_COLORS: Record<LineageStatus, string> = {
  open: "bg-[#E5E7EB] text-[#374151]",
  in_progress: "bg-[#DBEAFE] text-[#1E40AF]",
  resolved: "bg-[#DCFCE7] text-[#166534]",
  accepted_risk: "bg-[#FEF3C7] text-[#92400E]",
  false_positive: "bg-[#F3E8FF] text-[#6B21A8]",
  fixed: "bg-[#DCFCE7] text-[#166534]",
  regression: "bg-[#FEE2E2] text-[#991B1B]",
};

interface Props {
  status: LineageStatus;
}

export function LineageStatusBadge({ status }: Props) {
  const { t } = useTranslation();
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_COLORS[status] ?? STATUS_COLORS.open}`}
    >
      {t(`lineage.status_${status}`)}
    </span>
  );
}
