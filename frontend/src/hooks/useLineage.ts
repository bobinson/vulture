import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api.ts";
import { indexLineage, resolveLineage, type LineageIdentity } from "@/lib/lineage.ts";
import type { FindingLineage, LineageEvent, ProveResult } from "@/lib/types.ts";

interface LineageEdit {
  status: string;
  notes: string;
  ticketUrl: string;
}

interface UseLineageOptions {
  /**
   * 0096 follow-up: called with the updated row once a status save lands.
   * A triage changes what the backend serves as the audit's OWASP coverage
   * (triaged false positives are left out when the audit is read), so the
   * page uses this to re-fetch the audit.
   */
  onStatusSaved?: (updated: FindingLineage) => void;
}

// Edit state, the saved flag and the timeline are keyed by lineage ROW id:
// that is the thing being edited, and several findings can share a v1
// fingerprint while belonging to different rows.
export function useLineage(auditId?: string, { onStatusSaved }: UseLineageOptions = {}) {
  const [lineageRows, setLineageRows] = useState<FindingLineage[]>([]);
  const [timelineMap, setTimelineMap] = useState<Map<string, LineageEvent[]>>(new Map());
  const [showTimeline, setShowTimeline] = useState<string | null>(null);
  const [editingLineage, setEditingLineage] = useState<Map<string, LineageEdit>>(new Map());
  const [savedFeedback, setSavedFeedback] = useState<string | null>(null);
  const [proveHistoryMap, setProveHistoryMap] = useState<Map<string, ProveResult[]>>(new Map());
  const [error, setError] = useState<string | null>(null);

  const timelineMapRef = useRef(timelineMap);
  useEffect(() => { timelineMapRef.current = timelineMap; });

  const proveHistoryMapRef = useRef(proveHistoryMap);
  useEffect(() => { proveHistoryMapRef.current = proveHistoryMap; });

  const editingLineageRef = useRef(editingLineage);
  useEffect(() => { editingLineageRef.current = editingLineage; });

  // Read through a ref so saveStatus keeps one identity whatever callback
  // the caller passes on each render.
  const onStatusSavedRef = useRef(onStatusSaved);
  useEffect(() => { onStatusSavedRef.current = onStatusSaved; });

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(savedTimerRef.current), []);

  useEffect(() => {
    if (!auditId) return;
    api.getAuditLineage(auditId).then(setLineageRows).catch(() => {});
  }, [auditId]);

  const lineageIndex = useMemo(() => indexLineage(lineageRows), [lineageRows]);
  const lineageFor = useCallback(
    (item: LineageIdentity) => resolveLineage(lineageIndex, item),
    [lineageIndex],
  );

  const loadTimeline = useCallback((lineageId: string) => {
    if (timelineMapRef.current.has(lineageId)) {
      setShowTimeline((prev) => (prev === lineageId ? null : lineageId));
      return;
    }
    api.getLineageTimeline(lineageId).then((events) => {
      setTimelineMap((prev) => new Map(prev).set(lineageId, events));
      setShowTimeline(lineageId);
    }).catch(() => {});
  }, []);

  const updateEdit = useCallback((lineageId: string, partial: Partial<LineageEdit>) => {
    setEditingLineage((prev) => {
      const next = new Map(prev);
      const existing = prev.get(lineageId) ?? { status: "", notes: "", ticketUrl: "" };
      next.set(lineageId, { ...existing, ...partial });
      return next;
    });
  }, []);

  const loadProveHistory = useCallback((fingerprint: string) => {
    if (proveHistoryMapRef.current.has(fingerprint)) return;
    api.getProveResultsByFingerprint(fingerprint).then((results) => {
      setProveHistoryMap((prev) => new Map(prev).set(fingerprint, results));
    }).catch(() => {});
  }, []);

  const saveStatus = useCallback((lineageId: string) => {
    const edit = editingLineageRef.current.get(lineageId);
    if (!edit) return;
    setError(null);
    api.updateLineageStatus(lineageId, edit.status, edit.notes || undefined, edit.ticketUrl || undefined).then((updated) => {
      setLineageRows((prev) => prev.map((row) => (row.id === lineageId ? updated : row)));
      setSavedFeedback(lineageId);
      clearTimeout(savedTimerRef.current);
      savedTimerRef.current = setTimeout(() => setSavedFeedback((prev) => (prev === lineageId ? null : prev)), 2000);
      onStatusSavedRef.current?.(updated);
    }).catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to update lineage status");
    });
  }, []);

  return {
    lineageRows,
    lineageFor,
    timelineMap,
    showTimeline,
    editingLineage,
    savedFeedback,
    proveHistoryMap,
    error,
    loadTimeline,
    loadProveHistory,
    updateEdit,
    saveStatus,
  };
}
