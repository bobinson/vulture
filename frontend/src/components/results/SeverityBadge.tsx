import { useTranslation } from "react-i18next";
import { SEVERITY_COLORS } from "@/lib/constants.ts";
import type { Severity } from "@/lib/types.ts";

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const { t } = useTranslation();
  const colorClass = SEVERITY_COLORS[severity] ?? "severity-info";

  return (
    <span className={`badge uppercase ${colorClass}`}>
      {t(`severity.${severity}`)}
    </span>
  );
}
