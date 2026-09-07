/**
 * Report download panel.
 *
 * CWE-778 exception-family fixture for feature 0087. `.tsx` is absent from the
 * skill's extension gate today (defect B7), so every site below is invisible
 * to the shipped detector regardless of shape. Markers: `EXPECT: finding` /
 * `EXPECT: clean`; EXPECTATIONS.md records the line numbers.
 */
import { useCallback, useEffect, useState } from "react";

import { downloadReport, fetchReportMeta } from "./api";
import { logger } from "./logger";
import { ReportError } from "./errors";

interface ReportMeta {
  id: string;
  sizeBytes: number;
  generatedAt: string;
}

interface PanelProps {
  reportId: string;
  onDismiss: () => void;
}

export function ReportPanel({ reportId, onDismiss }: PanelProps): JSX.Element {
  const [meta, setMeta] = useState<ReportMeta | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load(): Promise<void> {
      try {
        const next = await fetchReportMeta(reportId);
        if (!cancelled) setMeta(next);
      } catch (err) { // EXPECT: finding -- id=tsx_swallow -- the panel silently renders empty
        if (!cancelled) setMeta(null);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [reportId]);

  const onDownload = useCallback(async () => {
    setBusy(true);
    try {
      await downloadReport(reportId);
    } catch (err) { // EXPECT: clean -- id=tsx_logs -- the failure is recorded
      logger.error({ err, reportId }, "report download failed");
    } finally {
      setBusy(false);
    }
  }, [reportId]);

  const onCopyLink = useCallback(() => {
    // EXPECT: clean -- id=tsx_header_line_log -- defect B1: single-line handler
    // whose only statement, the log call, is on the header line.
    try { void navigator.clipboard.writeText(`/reports/${reportId}`); } catch (err) { logger.warn({ err, reportId }, "clipboard write refused"); }
  }, [reportId]);

  const onRename = useCallback(async (name: string) => {
    try {
      await fetchReportMeta(`${reportId}?rename=${encodeURIComponent(name)}`);
    } catch (err) { // EXPECT: clean -- id=tsx_rethrow -- handed to the error boundary
      throw new ReportError(`rename of ${reportId} failed`, { cause: err });
    }
  }, [reportId]);

  const onPurge = useCallback(() => {
    try {
      window.localStorage.removeItem(`report:${reportId}`);
    } catch (err) { // EXPECT: finding -- id=tsx_scope_leak -- defect B2: the log
      onDismiss();  // call below belongs to onPanelRendered(), not to this handler
    }
  }, [reportId, onDismiss]);

  const onPanelRendered = useCallback(() => {
    logger.debug({ reportId, size: meta?.sizeBytes ?? 0 }, "report panel rendered");
  }, [reportId, meta]);

  return (
    <section className="report-panel" onAnimationEnd={onPanelRendered}>
      <h2>{meta ? meta.id : "loading"}</h2>
      <button type="button" disabled={busy} onClick={onDownload}>
        Download
      </button>
      <button type="button" onClick={onCopyLink}>
        Copy link
      </button>
      <button type="button" onClick={() => void onRename("renamed")}>
        Rename
      </button>
      <button type="button" onClick={onPurge}>
        Purge
      </button>
    </section>
  );
}

export function trackPanelClose(reportId: string): void {
  logger.info({ reportId }, "report panel closed");
}
