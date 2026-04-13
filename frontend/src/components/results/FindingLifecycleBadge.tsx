import { useTranslation } from "react-i18next";
import type { FindingLineage } from "@/lib/types.ts";

interface FindingLifecycleBadgeProps {
  lineage?: FindingLineage;
  currentAuditId?: string;
}

export function FindingLifecycleBadge({ lineage, currentAuditId }: FindingLifecycleBadgeProps) {
  const { t } = useTranslation();

  if (!lineage) return null;

  const isNew = lineage.first_audit_id === currentAuditId;
  const isRegression = lineage.current_status === "regression";

  if (isNew) {
    return (
      <span
        className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase bg-[#DBEAFE] text-[#1E40AF]"
        data-testid="lifecycle-badge-new"
      >
        {t("lineage.newBadge")}
      </span>
    );
  }

  if (isRegression) {
    return (
      <span
        className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase bg-[#FEE2E2] text-[#991B1B]"
        data-testid="lifecycle-badge-regression"
      >
        {t("lineage.regressionBadge")}
      </span>
    );
  }

  return null;
}
