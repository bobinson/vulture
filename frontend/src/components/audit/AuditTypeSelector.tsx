import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import type { AgentInfo } from "@/lib/types.ts";

function AgentIcon({ id }: { id: string }) {
  switch (id) {
    case "chaos":
      return (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
        </svg>
      );
    case "owasp":
      return (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      );
    case "soc2":
      return (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15a2.25 2.25 0 012.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
        </svg>
      );
    case "cwe":
      return (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0112 12.75zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 01-1.152-6.135 23.846 23.846 0 01.497-5.92A25.112 25.112 0 0012 2.25c-2.676 0-5.26.38-7.702 1.093a23.846 23.846 0 01.497 5.92 23.91 23.91 0 01-1.152 6.135A24.093 24.093 0 0112 12.75z" />
        </svg>
      );
    default:
      return (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
        </svg>
      );
  }
}

const AGENT_DESC_KEYS: Record<string, string> = {
  chaos: "audit.chaosDesc",
  owasp: "audit.owaspDesc",
  soc2: "audit.soc2Desc",
  cwe: "audit.cweDesc",
  xss: "audit.xssDesc",
  ssdf: "audit.ssdfDesc",
  do178c: "audit.do178cDesc",
  asvs: "audit.asvsDesc",
};

interface AuditTypeSelectorProps {
  selected: string[];
  onSelectionChange: (ids: string[]) => void;
}

export function AuditTypeSelector({ selected, onSelectionChange }: AuditTypeSelectorProps) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const { t } = useTranslation();

  useEffect(() => {
    api
      .getAgents()
      .then(setAgents)
      .catch(() => setAgents([]))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (id: string) => {
    if (selected.includes(id)) {
      onSelectionChange(selected.filter((s) => s !== id));
    } else {
      onSelectionChange([...selected, id]);
    }
  };

  return (
    <div className="card p-5 space-y-4" data-testid="audit-type-selector">
      <div>
        <p className="label">{t("audit.auditTypes")}</p>
        <p className="text-[12px] text-muted">{t("audit.auditTypesDesc")}</p>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-4">
          <div className="w-4 h-4 border-2 border-accent/30 border-t-accent rounded-full animate-spin" />
          <p className="text-[13px] text-muted">{t("common.loading")}</p>
        </div>
      ) : agents.length === 0 ? (
        <p className="text-[13px] text-muted py-4">{t("audit.noAgents")}</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {agents.map((agent) => {
            const isSelected = selected.includes(agent.id);
            const descKey = AGENT_DESC_KEYS[agent.id];
            const desc = descKey ? t(descKey) : (agent.description ?? "");
            return (
              <button
                key={agent.id}
                type="button"
                data-testid={`agent-checkbox-${agent.id}`}
                className={`text-left p-4 rounded-[10px] border transition-all duration-120 cursor-pointer ${
                  isSelected
                    ? "border-accent bg-accent/5"
                    : "border-border bg-surface hover:border-border-dark"
                }`}
                onClick={() => toggle(agent.id)}
              >
                <div className="flex items-start gap-3">
                  <span className={`mt-0.5 ${isSelected ? "text-accent" : "text-muted"}`}>
                    <AgentIcon id={agent.id} />
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-[13px] font-semibold text-foreground">
                        {agent.name}
                      </p>
                      {isSelected && (
                        <span className="w-4 h-4 rounded-full bg-accent flex items-center justify-center shrink-0">
                          <svg className="w-2.5 h-2.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-muted mt-1 leading-relaxed">
                      {desc}
                    </p>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
