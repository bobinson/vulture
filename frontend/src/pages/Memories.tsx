import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import type { AuditMemory, MemoryEdge } from "@/lib/types.ts";
import { SEVERITY_COLORS, agentLabel } from "@/lib/constants.ts";

const REMEDIATION_STATUSES = [
  "open",
  "in_progress",
  "resolved",
  "accepted_risk",
  "false_positive",
] as const;

const STATUS_COLORS: Record<string, string> = {
  open: "bg-red-100 text-red-700",
  in_progress: "bg-yellow-100 text-yellow-700",
  resolved: "bg-green-100 text-green-700",
  accepted_risk: "bg-blue-100 text-blue-700",
  false_positive: "bg-gray-100 text-gray-500",
};

export function Memories() {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<AuditMemory[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedMemory, setSelectedMemory] = useState<AuditMemory | null>(null);
  const [edges, setEdges] = useState<MemoryEdge[]>([]);
  const [editingStatus, setEditingStatus] = useState<string | null>(null);
  const [statusNotes, setStatusNotes] = useState("");

  const handleSearch = useCallback(async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const data = await api.searchMemories(query, 30);
      setResults(data);
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [query]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleSearch();
    },
    [handleSearch],
  );

  const selectMemory = useCallback(async (mem: AuditMemory) => {
    setSelectedMemory(mem);
    setEditingStatus(null);
    try {
      const data = await api.getMemoryWithEdges(mem.id);
      setEdges(data.edges ?? []);
    } catch {
      setEdges([]);
    }
  }, []);

  const handleStatusUpdate = useCallback(
    async (memId: string, status: string) => {
      try {
        await api.updateRemediation(memId, status, statusNotes);
        setResults((prev) =>
          prev.map((m) =>
            m.id === memId ? { ...m, remediation_status: status } : m,
          ),
        );
        if (selectedMemory?.id === memId) {
          setSelectedMemory((prev) =>
            prev ? { ...prev, remediation_status: status } : prev,
          );
        }
        setEditingStatus(null);
        setStatusNotes("");
      } catch {
        /* ignore */
      }
    },
    [statusNotes, selectedMemory],
  );

  // Load recent memories on mount
  useEffect(() => {
    api
      .searchMemories("", 20)
      .then(setResults)
      .catch(() => {});
  }, []);

  return (
    <div className="space-y-5">
      {/* Subtitle */}
      <p className="text-[13px] text-muted -mt-4">{t("memories.subtitle")}</p>

      {/* Search bar */}
      <div className="flex gap-2">
        <input
          type="text"
          className="input-field flex-1"
          placeholder={t("memories.searchPlaceholder")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          aria-label={t("memories.searchPlaceholder")}
        />
        <button
          type="button"
          className="btn-primary"
          onClick={handleSearch}
          disabled={loading}
        >
          {loading ? t("common.loading") : t("memories.search")}
        </button>
      </div>

      <div className="flex gap-5">
        {/* Results list */}
        <div className="flex-1 space-y-2">
          {results.length === 0 && !loading && (
            <div className="card p-8 text-center text-muted text-[13px]">
              {t("memories.noResults")}
            </div>
          )}
          {results.map((mem) => (
            <button
              key={mem.id}
              type="button"
              className={`card p-3 w-full text-left cursor-pointer transition-colors hover:border-accent/30 ${
                selectedMemory?.id === mem.id ? "border-accent/40 bg-accent/3" : ""
              }`}
              onClick={() => selectMemory(mem)}
            >
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`inline-flex px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded ${SEVERITY_COLORS[mem.severity] ?? "severity-info"}`}
                >
                  {t(`severity.${mem.severity}`)}
                </span>
                <span className="text-[11px] text-muted">
                  {agentLabel(mem.agent_type, t)}
                </span>
                <span
                  className={`ml-auto inline-flex px-1.5 py-0.5 text-[10px] font-medium rounded ${STATUS_COLORS[mem.remediation_status] ?? STATUS_COLORS.open}`}
                >
                  {t(`memories.status_${mem.remediation_status}`)}
                </span>
              </div>
              <p className="text-[13px] font-medium text-foreground truncate">
                {mem.title}
              </p>
              <p className="text-[12px] text-muted truncate mt-0.5">
                {mem.file_paths?.[0] ?? ""}
              </p>
              {mem.similarity != null && mem.similarity > 0 && (
                <div className="mt-1 flex items-center gap-1">
                  <div className="h-1 flex-1 bg-border rounded-full overflow-hidden">
                    <div
                      className="h-full bg-accent rounded-full"
                      style={{ width: `${Math.round(mem.similarity * 100)}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-muted">
                    {Math.round(mem.similarity * 100)}%
                  </span>
                </div>
              )}
            </button>
          ))}
        </div>

        {/* Detail panel */}
        {selectedMemory && (
          <div className="w-[380px] space-y-4 shrink-0">
            {/* Memory detail card */}
            <div className="card p-4 space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <span
                    className={`inline-flex px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded ${SEVERITY_COLORS[selectedMemory.severity] ?? "severity-info"}`}
                  >
                    {t(`severity.${selectedMemory.severity}`)}
                  </span>
                  <h3 className="text-[14px] font-semibold text-foreground mt-1">
                    {selectedMemory.title}
                  </h3>
                </div>
                <button
                  type="button"
                  className="text-muted hover:text-foreground text-[12px] cursor-pointer"
                  onClick={() => setSelectedMemory(null)}
                  aria-label={t("common.close")}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className="text-[12px] text-muted space-y-1">
                <p>
                  <span className="font-medium text-foreground">{t("memories.agent")}:</span>{" "}
                  {agentLabel(selectedMemory.agent_type, t)}
                </p>
                <p>
                  <span className="font-medium text-foreground">{t("results.category")}:</span>{" "}
                  {selectedMemory.category}
                </p>
                {selectedMemory.file_paths?.length > 0 && (
                  <p>
                    <span className="font-medium text-foreground">{t("results.file")}:</span>{" "}
                    {selectedMemory.file_paths.join(", ")}
                  </p>
                )}
              </div>

              <div className="text-[12px] text-foreground/80 leading-relaxed">
                {selectedMemory.content}
              </div>

              {selectedMemory.remediation_notes && (
                <div className="bg-cream-dark rounded-lg p-2.5 text-[12px]">
                  <p className="font-medium text-foreground mb-0.5">
                    {t("results.recommendation")}
                  </p>
                  <p className="text-muted">{selectedMemory.remediation_notes}</p>
                </div>
              )}

              {/* Keywords */}
              {selectedMemory.keywords?.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {selectedMemory.keywords.map((kw) => (
                    <span
                      key={kw}
                      className="px-1.5 py-0.5 bg-cream-dark text-muted text-[10px] rounded"
                    >
                      {kw}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Remediation status */}
            <div className="card p-4 space-y-2">
              <p className="text-[12px] font-medium text-foreground">
                {t("memories.remediation")}
              </p>
              {editingStatus === selectedMemory.id ? (
                <div className="space-y-2">
                  <div className="flex flex-wrap gap-1">
                    {REMEDIATION_STATUSES.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className={`px-2 py-1 text-[11px] rounded-md border cursor-pointer transition-colors ${
                          selectedMemory.remediation_status === s
                            ? "border-accent bg-accent/5 text-accent"
                            : "border-border text-muted hover:border-accent/30"
                        }`}
                        onClick={() =>
                          handleStatusUpdate(selectedMemory.id, s)
                        }
                      >
                        {t(`memories.status_${s}`)}
                      </button>
                    ))}
                  </div>
                  <textarea
                    className="input-field text-[12px] min-h-[60px]"
                    placeholder={t("memories.notesPlaceholder")}
                    value={statusNotes}
                    onChange={(e) => setStatusNotes(e.target.value)}
                  />
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-1 text-[11px] font-medium rounded ${STATUS_COLORS[selectedMemory.remediation_status] ?? STATUS_COLORS.open}`}
                  >
                    {t(`memories.status_${selectedMemory.remediation_status}`)}
                  </span>
                  <button
                    type="button"
                    className="text-[11px] text-accent hover:underline cursor-pointer"
                    onClick={() => setEditingStatus(selectedMemory.id)}
                  >
                    {t("memories.changeStatus")}
                  </button>
                </div>
              )}
            </div>

            {/* Related memories (edges) */}
            {edges.length > 0 && (
              <div className="card p-4 space-y-2">
                <p className="text-[12px] font-medium text-foreground">
                  {t("memories.relatedMemories")}
                </p>
                {edges.map((edge) => (
                  <div
                    key={edge.id}
                    className="flex items-center gap-2 text-[11px] py-1.5 border-b border-border last:border-0"
                  >
                    <span className="text-accent font-medium shrink-0">
                      {t(`memories.relation_${edge.relation_type}`)}
                    </span>
                    <div className="flex-1 min-w-0">
                      {edge.target_title ? (
                        <div className="flex items-center gap-1.5">
                          {edge.target_severity && (
                            <span className={`inline-flex px-1 py-0 text-[9px] font-semibold uppercase rounded ${SEVERITY_COLORS[edge.target_severity] ?? "severity-info"}`}>
                              {edge.target_severity.charAt(0)}
                            </span>
                          )}
                          <span className="text-foreground/80 truncate" title={edge.target_title}>
                            {edge.target_title}
                          </span>
                        </div>
                      ) : (
                        <span className="text-muted truncate">
                          {edge.target_id === selectedMemory.id ? edge.source_id : edge.target_id}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <div className="w-8 h-1 bg-border rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent rounded-full"
                          style={{ width: `${Math.round(edge.strength * 100)}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-muted">
                        {Math.round(edge.strength * 100)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
