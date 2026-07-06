import { memo } from "react";
import { useTranslation } from "react-i18next";
import { Chip } from "@/components/shared/Chip.tsx";

// Feature 0058 (R6) — provenance chip on findings. Thin wrapper over
// the shared Chip labeled with the finding's detection tier (e.g.
// "semgrep", "signature", "skill"). Renders nothing when the finding
// carries no provenance so pre-0058 findings are unchanged.

interface ProvenanceChipProps {
  provenance?: string;
}

function ProvenanceChipImpl({ provenance }: ProvenanceChipProps) {
  const { t } = useTranslation();

  if (!provenance) return null;

  return (
    <Chip
      label={provenance}
      tone="info"
      title={t("results.provenance")}
      testId="provenance-chip"
    />
  );
}

export const ProvenanceChip = memo(ProvenanceChipImpl);
