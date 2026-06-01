import { useTranslation } from "react-i18next";

// ValidationBadge surfaces the validate-phase (0045 L1-L5) verdict on a
// finding. It renders ONLY for the two "needs scrutiny" states so the
// table stays clean:
//   - likely_fp  → the automatic false-positive verdict (purple)
//   - suspicious → demoted but not dismissed (amber)
// high_confidence and empty/unknown (pre-0045) render nothing — they're
// the default-trust state and don't warrant a chip on every row.
const STATUS_COLORS: Record<string, string> = {
  likely_fp: "bg-[#F3E8FF] text-[#6B21A8]",
  suspicious: "bg-[#FEF3C7] text-[#92400E]",
};

interface Props {
  status?: string;
}

export function ValidationBadge({ status }: Props) {
  const { t } = useTranslation();
  if (!status || !(status in STATUS_COLORS)) {
    return null;
  }
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_COLORS[status]}`}
      title={t("results.validation.tooltip")}
    >
      {t(`results.validation.${status}`)}
    </span>
  );
}
