import { useTranslation } from "react-i18next";
import { Chip } from "@/components/shared/Chip.tsx";
import { owaspLabels } from "@/lib/compliance.ts";
import type { Finding } from "@/lib/types.ts";

interface OwaspChipProps {
  id: string;
  edition: string;
  /** Absent on a lineage row, which stores category ids only. */
  name?: string;
}

/**
 * Feature 0096: one OWASP Top 10 label, shown as its category id (A07). The
 * tooltip names the category and the edition, because "A07" alone means a
 * different thing in 2021 and 2025.
 */
export function OwaspChip({ id, edition, name }: OwaspChipProps) {
  const { t } = useTranslation();
  const title = name
    ? t("results.owaspChipTitle", { id, name, edition })
    : t("results.owaspChipTitleShort", { id, edition });
  return <Chip label={id} tone="info" title={title} testId="owasp-chip" />;
}

/** Every OWASP label of a finding, one chip each; nothing when unlabelled. */
export function FindingOwaspChips({ finding }: { finding: Finding }) {
  const labels = owaspLabels(finding);
  if (labels.length === 0) return null;
  return (
    <>
      {labels.map((l) => (
        <OwaspChip
          key={`${l.edition}/${l.category_id}`}
          id={l.category_id}
          name={l.category_name}
          edition={l.edition}
        />
      ))}
    </>
  );
}
