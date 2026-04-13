import { useTranslation } from "react-i18next";

interface CrossAgentBadgeProps {
  origins?: string[];
}

export function CrossAgentBadge({ origins }: CrossAgentBadgeProps) {
  const { t } = useTranslation();

  if (!origins || origins.length === 0) return null;

  return (
    <span className="text-[9px] italic text-muted-light" data-testid="cross-agent-badge">
      {t("crossAgent.alsoDetected")}: {origins.join(", ")}
    </span>
  );
}
