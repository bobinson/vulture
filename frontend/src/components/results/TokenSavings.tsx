import { useTranslation } from "react-i18next";
import type { TokenSavings as TokenSavingsType, DedupStats } from "@/lib/types.ts";

interface Props {
  savings?: TokenSavingsType | null;
  dedupStats?: DedupStats | null;
}

export function TokenSavings({ savings, dedupStats }: Props) {
  const { t } = useTranslation();

  // Skill mode: show dedup stats (no token claims)
  if (dedupStats && (dedupStats.findings_deduped > 0 || dedupStats.duplicates_removed > 0)) {
    return (
      <div
        data-testid="dedup-stats"
        className="card px-4 py-3 flex items-center gap-4 text-[12px] border-l-2 border-accent"
      >
        <svg
          className="w-4 h-4 text-accent shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"
          />
        </svg>
        <div className="flex items-center gap-3 flex-wrap">
          {dedupStats.findings_deduped > 0 && (
            <span className="font-semibold text-accent">
              {t("results.findingsDeduped", { count: dedupStats.findings_deduped })}
            </span>
          )}
          {dedupStats.prior_findings_used > 0 && (
            <span className="text-muted">
              {t("results.priorFindings", { count: dedupStats.prior_findings_used })}
            </span>
          )}
          {dedupStats.duplicates_removed > 0 && (
            <span className="text-muted-light">
              {t("results.duplicatesRemoved", { count: dedupStats.duplicates_removed })}
            </span>
          )}
        </div>
      </div>
    );
  }

  // LLM mode: show token savings
  if (!savings || savings.tokens_saved <= 0) return null;

  return (
    <div
      data-testid="token-savings"
      className="card px-4 py-3 flex items-center gap-4 text-[12px] border-l-2 border-success"
    >
      <svg
        className="w-4 h-4 text-success shrink-0"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M13 10V3L4 14h7v7l9-11h-7z"
        />
      </svg>
      <div className="flex items-center gap-3 flex-wrap">
        <span className="font-semibold text-success">
          {savings.savings_pct}% {t("results.tokensSaved")}
        </span>
        <span className="text-muted">
          {savings.tokens_saved.toLocaleString()} {t("results.tokens")}
        </span>
        {savings.prior_findings_used > 0 && (
          <span className="text-muted-light">
            {t("results.priorFindings", { count: savings.prior_findings_used })}
          </span>
        )}
        {savings.duplicates_removed > 0 && (
          <span className="text-muted-light">
            {t("results.duplicatesRemoved", { count: savings.duplicates_removed })}
          </span>
        )}
        <span className="text-muted-light italic">
          {t("results.estimated")}
        </span>
      </div>
    </div>
  );
}
