import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api.ts";
import type { FindingLineage, LineageEvent, ProveResult } from "@/lib/types.ts";

interface LineageEdit {
  status: string;
  notes: string;
  ticketUrl: string;
}

export function useLineage(auditId?: string) {
  const [lineageMap, setLineageMap] = useState<Map<string, FindingLineage>>(new Map());
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

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(savedTimerRef.current), []);

  useEffect(() => {
    if (!auditId) return;
    api.getAuditLineage(auditId).then((lineages) => {
      const map = new Map<string, FindingLineage>();
      for (const l of lineages) {
        map.set(l.fingerprint, l);
      }
      setLineageMap(map);
    }).catch(() => {});
  }, [auditId]);

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

  const updateEdit = useCallback((fingerprint: string, partial: Partial<LineageEdit>) => {
    setEditingLineage((prev) => {
      const next = new Map(prev);
      const existing = prev.get(fingerprint) ?? { status: "", notes: "", ticketUrl: "" };
      next.set(fingerprint, { ...existing, ...partial });
      return next;
    });
  }, []);

  const loadProveHistory = useCallback((fingerprint: string) => {
    if (proveHistoryMapRef.current.has(fingerprint)) return;
    api.getProveResultsByFingerprint(fingerprint).then((results) => {
      setProveHistoryMap((prev) => new Map(prev).set(fingerprint, results));
    }).catch(() => {});
  }, []);

  const saveStatus = useCallback((lineageId: string, fingerprint: string) => {
    const edit = editingLineageRef.current.get(fingerprint);
    if (!edit) return;
    setError(null);
    api.updateLineageStatus(lineageId, edit.status, edit.notes || undefined, edit.ticketUrl || undefined).then((updated) => {
      setLineageMap((prev) => new Map(prev).set(fingerprint, updated));
      setSavedFeedback(fingerprint);
      clearTimeout(savedTimerRef.current);
      savedTimerRef.current = setTimeout(() => setSavedFeedback((prev) => (prev === fingerprint ? null : prev)), 2000);
    }).catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to update lineage status");
    });
  }, []);

  return {
    lineageMap,
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
