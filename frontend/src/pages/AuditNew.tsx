import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { SourceInput } from "@/components/audit/SourceInput.tsx";
import { AuditTypeSelector } from "@/components/audit/AuditTypeSelector.tsx";
import { LLMDegradedBanner } from "@/components/results/LLMDegradedBanner.tsx";
import { useSource, validateGitUrl, validateLocalPath } from "@/hooks/useSource.ts";
import { useAudit } from "@/hooks/useAudit.ts";
import { ROUTES } from "@/lib/constants.ts";
import { api } from "@/lib/api.ts";
import type { Audit } from "@/lib/types.ts";

export function AuditNew() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { submitSource } = useSource();
  const { createAudit } = useAudit();

  const [sourceType, setSourceType] = useState<"git" | "local">("local");
  const [value, setValue] = useState("");
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [cachedAudit, setCachedAudit] = useState<Audit | null>(null);

  const handleSubmit = useCallback(async () => {
    const validationError =
      sourceType === "git" ? validateGitUrl(value) : validateLocalPath(value);
    if (validationError) {
      setError(validationError);
      return;
    }

    if (selectedAgents.length === 0) {
      setError(t("audit.selectAtLeast"));
      return;
    }

    setError(null);
    setLoading(true);
    setCachedAudit(null);

    try {
      const source = await submitSource(sourceType, value);
      if (!source) {
        setError(t("errors.sourceFailed"));
        return;
      }

      // Check for cached results before running a new audit
      try {
        const cacheResult = await api.checkCache(source.id, selectedAgents);
        if (cacheResult.cached && cacheResult.audit) {
          setCachedAudit(cacheResult.audit);
          setLoading(false);
          return;
        }
      } catch {
        // Cache check failed, proceed with new audit
      }

      const audit = await createAudit(source.id, selectedAgents);
      if (audit) {
        navigate(ROUTES.AUDIT_RESULTS(audit.id));
      } else {
        setError(t("errors.auditFailed"));
      }
    } finally {
      setLoading(false);
    }
  }, [sourceType, value, selectedAgents, submitSource, createAudit, navigate, t]);

  const handleUseCached = useCallback(() => {
    if (cachedAudit) {
      navigate(ROUTES.AUDIT_RESULTS(cachedAudit.id));
    }
  }, [cachedAudit, navigate]);

  const handleRunFresh = useCallback(async () => {
    setCachedAudit(null);
    setLoading(true);
    try {
      const source = await submitSource(sourceType, value);
      if (!source) {
        setError(t("errors.sourceFailed"));
        return;
      }
      const audit = await createAudit(source.id, selectedAgents);
      if (audit) {
        navigate(ROUTES.AUDIT_RESULTS(audit.id));
      } else {
        setError(t("errors.auditFailed"));
      }
    } finally {
      setLoading(false);
    }
  }, [sourceType, value, selectedAgents, submitSource, createAudit, navigate, t]);

  return (
    <div className="max-w-3xl space-y-5">
      <p className="text-[13px] text-muted -mt-4 mb-2">{t("audit.subtitle")}</p>

      <LLMDegradedBanner />

      <SourceInput
        sourceType={sourceType}
        onTypeChange={setSourceType}
        value={value}
        onChange={(v) => {
          setValue(v);
          setError(null);
          setCachedAudit(null);
        }}
        error={error}
      />

      <AuditTypeSelector
        selected={selectedAgents}
        onSelectionChange={(agents) => {
          setSelectedAgents(agents);
          setCachedAudit(null);
        }}
      />

      {cachedAudit && (
        <div className="bg-accent/5 border border-accent/20 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-accent shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <p className="text-sm font-medium text-foreground">
              {t("audit.cacheFound")}
            </p>
          </div>
          <p className="text-xs text-muted">
            {t("audit.cacheDescription", {
              count: cachedAudit.findings?.length ?? 0,
              date: cachedAudit.completed_at
                ? new Date(cachedAudit.completed_at).toLocaleDateString()
                : "",
            })}
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              className="btn-primary flex-1 py-2"
              onClick={handleUseCached}
            >
              {t("audit.useCached")}
            </button>
            <button
              type="button"
              className="btn-secondary flex-1 py-2"
              onClick={handleRunFresh}
              disabled={loading}
            >
              {loading ? t("audit.starting") : t("audit.runFresh")}
            </button>
          </div>
        </div>
      )}

      {!cachedAudit && (
        <button
          type="button"
          data-testid="audit-submit-button"
          className="btn-primary w-full py-3"
          disabled={loading}
          onClick={handleSubmit}
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              {t("audit.starting")}
            </>
          ) : (
            <>
              {t("audit.startAudit")}
              <span>{"\u2192"}</span>
            </>
          )}
        </button>
      )}
    </div>
  );
}
