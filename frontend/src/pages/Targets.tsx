import { useTranslation } from "react-i18next";
import { useTargets } from "@/hooks/useTargets.ts";
import { TargetsList } from "@/components/targets/TargetsList.tsx";

/**
 * The target list as a page of its own (`/targets`).
 *
 * Feature 0091 makes the codebase, not the individual run, the unit a reader
 * navigates by: pick a target, land on its aggregate report. The same list is
 * embedded at the top of the dashboard, so both entry points show one thing.
 */
export function Targets() {
  const { t } = useTranslation();
  const { targets, loading, error, reload } = useTargets();

  return (
    <div className="max-w-5xl space-y-4">
      <p className="text-[13px] text-muted -mt-4">{t("targets.subtitle")}</p>
      <TargetsList targets={targets} loading={loading} error={error} onRetry={reload} />
    </div>
  );
}
