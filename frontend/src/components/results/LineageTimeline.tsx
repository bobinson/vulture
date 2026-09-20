import { memo } from "react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ROUTES } from "@/lib/constants.ts";
import { eventNoteText, reasonText } from "@/lib/lineage.ts";
import { formatScanStamp } from "@/lib/targets.ts";
import type { LineageEvent, LineageEvidence } from "@/lib/types.ts";

/**
 * Tone per event type. Feature 0091 added nine event types to the five that
 * existed; the tone says what the event MEANS for the finding, which is not
 * the same as whether the scan succeeded:
 *
 *   green   the finding is gone (`fixed`, `evidence_gone`)
 *   red     it is back (`regression`)
 *   amber   it is confirmed STILL THERE (`confirmed_by_evidence`) — the scan
 *           went well and the news is bad
 *   orange  the scan could not decide (`unconfirmable`)
 *   grey    the scan says nothing either way (out of scope, unknown scope,
 *           absent from the result, skipped because the tier was degraded)
 *   muted   bookkeeping (`memory_synced`, `merged`, status/note edits)
 *
 * An unknown event type falls back to muted rather than disappearing: a newer
 * backend must never make an event invisible in an older build.
 */
const EVENT_TONE: Record<string, string> = {
  detected: "bg-accent",
  fixed: "bg-success",
  evidence_gone: "bg-success",
  regression: "bg-danger",
  confirmed_by_evidence: "bg-warning",
  unconfirmable: "bg-[#F97316]",
  out_of_scope: "bg-border-dark",
  scope_unknown: "bg-border-dark",
  absent_in_result: "bg-border-dark",
  skipped_degraded: "bg-border-dark",
  memory_synced: "bg-muted-light",
  merged: "bg-muted-light",
  status_change: "bg-muted-light",
  note_added: "bg-muted-light",
};

/**
 * "3 days ago" / "just now". Every branch goes through `t`: the previous
 * version hard-coded the English suffixes, so a French or Japanese reader saw
 * "3d ago" in the middle of a translated page.
 */
function formatRelativeTime(dateStr: string, t: TFunction): string {
  const then = new Date(dateStr).getTime();
  if (Number.isNaN(then)) return dateStr;
  const diffMin = Math.floor((Date.now() - then) / 60000);
  const diffHr = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  if (diffDay > 7) {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }
  if (diffDay > 0) return t("lineage.timeDays", { count: diffDay });
  if (diffHr > 0) return t("lineage.timeHours", { count: diffHr });
  if (diffMin > 0) return t("lineage.timeMinutes", { count: diffMin });
  return t("lineage.timeNow");
}

/**
 * A status as a human reads it. Falls back to the raw value rather than to
 * "lineage.status_whatever" so a status this build has never heard of still
 * renders as something, not as a key.
 */
function statusLabel(status: string, t: TFunction): string {
  return t(`lineage.status_${status}`, { defaultValue: status });
}

interface EventRowProps {
  event: LineageEvent;
  isLast: boolean;
  linkToScans: boolean;
}

const EventRow = memo(function EventRow({ event, isLast, linkToScans }: EventRowProps) {
  const { t } = useTranslation();
  const tone = EVENT_TONE[event.event_type] ?? "bg-muted-light";
  // A scanner note becomes a sentence; a note a person typed is left alone.
  // The raw value stays on `title` so an untranslatable one is still
  // inspectable without being printed as prose.
  const note = eventNoteText(event.event_type, event.notes, t);

  return (
    <div data-testid={`timeline-event-${event.event_type}`} className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className="flex items-center justify-center w-6 h-6">
          <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${tone}`} />
        </div>
        {!isLast && <div className="w-px flex-1 min-h-3 bg-border" />}
      </div>

      <div className="flex-1 pb-3 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          {/* defaultValue, so an event type this build has never heard of
              renders its own name rather than the string
              "lineage.event_whatever" — the same rule statusLabel follows. */}
          <span className="text-[12px] font-medium text-foreground">
            {t(`lineage.event_${event.event_type}`, { defaultValue: event.event_type })}
          </span>
          <span className="text-[11px] text-muted-light">
            {formatRelativeTime(event.created_at, t)}
          </span>
          {linkToScans && event.audit_id && (
            <Link
              to={ROUTES.AUDIT_RESULTS(event.audit_id)}
              className="text-[11px] font-mono text-accent hover:underline rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              title={t("scanHistory.openScan", { when: formatScanStamp(event.created_at) })}
            >
              {event.audit_id.slice(0, 8)}
            </Link>
          )}
        </div>

        {event.event_type === "status_change" && event.old_status && event.new_status && (
          <p className="text-[11px] text-muted mt-0.5">
            {statusLabel(event.old_status, t)} &rarr; {statusLabel(event.new_status, t)}
          </p>
        )}

        {(event.git_commit || event.git_branch) && (
          <div className="flex items-center gap-2 mt-1">
            {event.git_commit && (
              <span className="text-[10px] font-mono bg-cream rounded px-1.5 py-0.5 text-muted">
                {event.git_commit.slice(0, 7)}
              </span>
            )}
            {event.git_branch && (
              <span className="text-[10px] text-muted-light">
                {t("lineage.branch")}: {event.git_branch}
              </span>
            )}
          </div>
        )}

        {note && (
          <p
            data-testid="timeline-event-note"
            className="text-[11px] text-muted mt-1 break-words"
            title={event.notes}
          >
            {note}
          </p>
        )}
      </div>
    </div>
  );
});

/** The last evidence re-read of the cited file, rendered above the events. */
function EvidenceSummary({ evidence }: { evidence: LineageEvidence }) {
  const { t } = useTranslation();
  const reason = reasonText(evidence.reason, t);
  const window =
    evidence.line_start && evidence.line_end
      ? `${evidence.line_start}–${evidence.line_end}`
      : evidence.line_start
        ? String(evidence.line_start)
        : null;

  return (
    <div
      data-testid="lineage-evidence"
      className="rounded-md border border-border bg-cream/60 px-3 py-2 mb-3"
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
          {t("lineage.evidenceCheck")}
        </span>
        <span
          data-testid="lineage-evidence-outcome"
          data-outcome={evidence.last_outcome}
          className="text-[11px] font-medium text-foreground"
        >
          {t(`lineage.evidence_${evidence.last_outcome}`, {
            defaultValue: t("lineage.evidence_unconfirmable"),
          })}
        </span>
        {evidence.checked_at && (
          <span className="text-[11px] text-muted-light">
            {formatRelativeTime(evidence.checked_at, t)}
          </span>
        )}
      </div>
      {reason && (
        <p
          data-testid="lineage-evidence-reason"
          className="text-[11px] text-muted mt-1"
          title={evidence.reason}
        >
          {reason}
        </p>
      )}
      <div className="flex items-center gap-3 mt-1 flex-wrap">
        {window && (
          <span className="text-[10px] font-mono text-muted">
            {t("lineage.evidenceLines")}: {window}
          </span>
        )}
        {/* The file hash is a fingerprint of the file at check time. It says
            nothing to a reader on its own, so it is labelled and hidden behind
            a hover rather than printed as a bare 64-character blob. */}
        {evidence.file_hash && (
          <span
            className="text-[10px] font-mono text-muted-light truncate max-w-[16rem]"
            title={`${t("lineage.evidenceFileHash")}: ${evidence.file_hash}`}
          >
            {t("lineage.evidenceFileHash")}: {evidence.file_hash.slice(0, 12)}
          </span>
        )}
      </div>
    </div>
  );
}

interface LineageTimelineProps {
  events: LineageEvent[];
  /** The last evidence re-read, when the backend recorded one. */
  evidence?: LineageEvidence | null;
  /**
   * Whether each occurrence links to the scan that produced it. Off inside the
   * findings table, where the timeline is an inline detail of a row that is
   * already scoped to one scan.
   */
  linkToScans?: boolean;
}

/**
 * The life of one finding: the evidence check that decided its current status,
 * then every event recorded against it.
 */
export function LineageTimeline({ events, evidence, linkToScans = true }: LineageTimelineProps) {
  const { t } = useTranslation();

  if (events.length === 0 && !evidence) {
    return <p className="text-[12px] text-muted-light">{t("lineage.noLineage")}</p>;
  }

  return (
    <div>
      {evidence && <EvidenceSummary evidence={evidence} />}
      <div className="space-y-0">
        {events.map((event, i) => (
          <EventRow
            key={event.id}
            event={event}
            isLast={i === events.length - 1}
            linkToScans={linkToScans}
          />
        ))}
      </div>
    </div>
  );
}
