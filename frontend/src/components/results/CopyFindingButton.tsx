import { useTranslation } from "react-i18next";
import { useCopyFeedback } from "@/hooks/useCopyFeedback.ts";
import { findingToMarkdown } from "@/lib/markdown.ts";
import type { Finding } from "@/lib/types.ts";

interface CopyFindingButtonProps {
  finding: Finding;
  auditId?: string;
}

export function CopyFindingButton({ finding, auditId }: CopyFindingButtonProps) {
  const { t } = useTranslation();
  const { copied, onCopy } = useCopyFeedback();

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    void onCopy(findingToMarkdown(finding, auditId));
  };

  return (
    <button
      type="button"
      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded-md transition-colors cursor-pointer text-muted hover:text-foreground hover:bg-cream-dark"
      onClick={handleClick}
    >
      {copied ? (
        <>
          <svg className="w-3.5 h-3.5 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          {t("results.copied")}
        </>
      ) : (
        <>
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          {t("results.copyIssue")}
        </>
      )}
    </button>
  );
}
