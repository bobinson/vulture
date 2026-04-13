import { useTranslation } from "react-i18next";
import { useCopyFeedback } from "@/hooks/useCopyFeedback.ts";
import type { AuditComparison, Source } from "@/lib/types.ts";

interface GitContextHeaderProps {
  source: Source | null;
  comparison: AuditComparison | null;
  previousAuditId?: string;
}

export function GitContextHeader({ source, comparison, previousAuditId }: GitContextHeaderProps) {
  const { t } = useTranslation();
  const { copied, onCopy } = useCopyFeedback();

  const hasBranch = source?.git_branch;
  const hasCommit = source?.git_commit_short;
  const hasGit = hasBranch || hasCommit;

  if (!hasGit && !comparison) return null;

  return (
    <div className="card px-4 py-3 space-y-2" data-testid="git-context-header">
      <div className="flex items-center gap-4 text-[12px] text-muted">
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
        </svg>
        <span className="font-semibold uppercase tracking-wider text-[11px]">{t("lineage.gitContext")}</span>
        {hasBranch && (
          <span>
            {t("lineage.branch")}: <span className="font-mono bg-cream rounded px-2 py-0.5" data-testid="git-branch">{source.git_branch}</span>
          </span>
        )}
        {hasCommit && (
          <span className="flex items-center gap-1">
            {t("lineage.commit")}:{" "}
            <span className="font-mono bg-cream rounded px-2 py-0.5" data-testid="git-commit">{source.git_commit_short}</span>
            {source.git_commit_hash && (
              <button
                type="button"
                className="text-muted-light hover:text-foreground transition-colors cursor-pointer"
                title={t("lineage.copyCommit")}
                onClick={() => void onCopy(source.git_commit_hash!)}
              >
                {copied ? (
                  <svg className="w-3 h-3 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                )}
              </button>
            )}
          </span>
        )}
        {source?.git_remote_url && (
          <span className="text-muted-light truncate max-w-xs" title={source.git_remote_url}>
            {source.git_remote_url}
          </span>
        )}
      </div>

      {/* Comparison delta */}
      {comparison && comparison.has_previous && (
        <div className="flex items-center gap-3 text-[11px]" data-testid="comparison-delta">
          <span className="text-muted">
            {t("comparison.vsLabel")}{" "}
            {previousAuditId && (
              <a href={`/audits/${comparison.previous_audit_id}`} className="font-mono text-accent hover:underline">
                {comparison.previous_audit_id?.slice(0, 7)}
              </a>
            )}
            {!previousAuditId && (
              <span className="font-mono">{comparison.previous_audit_id?.slice(0, 7)}</span>
            )}
            {comparison.previous_date && (
              <span className="ml-1">
                ({new Date(comparison.previous_date).toLocaleDateString(undefined, { month: "short", day: "numeric" })})
              </span>
            )}
            :
          </span>
          {comparison.new_count > 0 && (
            <span className="text-[#D97706] font-medium" data-testid="delta-new">+{comparison.new_count} {t("comparison.newTab").toLowerCase()}</span>
          )}
          {comparison.fixed_count > 0 && (
            <span className="text-[#22C55E] font-medium" data-testid="delta-fixed">{"\u2713"}{comparison.fixed_count} {t("comparison.fixedTab").toLowerCase()}</span>
          )}
          {comparison.persistent_count > 0 && (
            <span className="text-muted-light font-medium">={comparison.persistent_count} {t("comparison.persistentTab").toLowerCase()}</span>
          )}
          {comparison.changed_count > 0 && (
            <span className="text-[#D97706] font-medium">~{comparison.changed_count} {t("comparison.changedTab").toLowerCase()}</span>
          )}
          {comparison.regression_count > 0 && (
            <span className="text-[#CF222E] font-medium" data-testid="delta-regression">{"\u21BA"}{comparison.regression_count} regression</span>
          )}
        </div>
      )}

      {/* First scan badge */}
      {comparison && !comparison.has_previous && (
        <div className="flex items-center gap-2" data-testid="first-scan-badge">
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-[#DBEAFE] text-[#1E40AF]">
            {t("comparison.firstScan")}
          </span>
        </div>
      )}
    </div>
  );
}
