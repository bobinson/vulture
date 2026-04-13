import { useTranslation } from "react-i18next";
import type { ProveStatus } from "@/lib/types.ts";

const STATUS_COLORS: Record<ProveStatus, string> = {
  verified: "bg-[#FEE2E2] text-[#991B1B]",
  not_reproduced: "bg-[#DCFCE7] text-[#166534]",
  inconclusive: "bg-[#FEF3C7] text-[#92400E]",
  skipped: "bg-[#F3F4F6] text-[#6B7280]",
};

export type ProvePhase = "planning" | "reviewing" | "executing" | "reflecting";

const PHASE_COLORS: Record<ProvePhase, string> = {
  planning: "bg-[#DBEAFE] text-[#1E40AF]",
  reviewing: "bg-[#E0E7FF] text-[#3730A3]",
  executing: "bg-[#FEF3C7] text-[#92400E]",
  reflecting: "bg-[#F3E8FF] text-[#6B21A8]",
};

interface Props {
  status: ProveStatus;
  phase?: ProvePhase;
}

export function ProveStatusBadge({ status, phase }: Props) {
  const { t } = useTranslation();

  // Show live phase when available (in-progress finding)
  if (phase) {
    return (
      <span
        className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium ${PHASE_COLORS[phase] ?? PHASE_COLORS.planning}`}
      >
        {phase}
      </span>
    );
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_COLORS[status] ?? STATUS_COLORS.skipped}`}
    >
      {t(`prove.${status === "not_reproduced" ? "notReproduced" : status}`)}
    </span>
  );
}
