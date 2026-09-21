import { useTranslation } from "react-i18next";
import type { AuditComparison } from "@/lib/types.ts";

interface CarriedForwardBannerProps {
  comparison: AuditComparison | null;
}

/**
 * "N findings from earlier scans were carried forward on this scan."
 *
 * Feature 0091 (LLD 10.2). Without it, a results page reads as if every row
 * were discovered just now; the count says how much of it the previous scans
 * already knew about, and points at the target report where the whole history
 * of each of those findings lives.
 *
 * Nothing carried forward — a first scan, or a scan whose findings are all new
 * — renders nothing rather than a zero.
 */
export function CarriedForwardBanner({ comparison }: CarriedForwardBannerProps) {
  const { t } = useTranslation();
  const carried = (comparison?.persistent_count ?? 0) + (comparison?.regression_count ?? 0);
  if (!comparison?.has_previous || carried <= 0) return null;

  return (
    <div
      data-testid="carried-forward-banner"
      className="rounded-md border border-border bg-cream/70 px-4 py-2.5 flex items-center gap-2 flex-wrap"
    >
      <span className="text-[12px] text-foreground">
        {t("scanHistory.carriedForward", { count: carried })}
      </span>
      {comparison.regression_count > 0 && (
        <span className="text-[11px] font-medium text-[#991B1B] bg-[#FEE2E2] rounded-full px-2 py-0.5 tabular-nums">
          {t("scanHistory.carriedRegressions", { count: comparison.regression_count })}
        </span>
      )}
    </div>
  );
}
