import { memo } from "react";
import { useTranslation } from "react-i18next";
import { SEVERITY_COLORS } from "@/lib/constants.ts";
import type { Severity } from "@/lib/types.ts";

interface SeverityBadgeProps {
  severity: Severity;
}

// memo'd: rendered hundreds of times per FindingsTable page. Without
// memoization, every parent re-render (filter / sort / expand toggle)
// reconciled all instances even though `severity` rarely changes.
function SeverityBadgeImpl({ severity }: SeverityBadgeProps) {
  const { t } = useTranslation();
  const colorClass = SEVERITY_COLORS[severity] ?? "severity-info";

  return (
    <span className={`badge uppercase ${colorClass}`}>
      {t(`severity.${severity}`)}
    </span>
  );
}

export const SeverityBadge = memo(SeverityBadgeImpl);
