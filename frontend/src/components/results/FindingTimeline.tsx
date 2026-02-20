import { useTranslation } from "react-i18next";
import type { LineageEvent } from "@/lib/types.ts";

interface FindingTimelineProps {
  events: LineageEvent[];
}

function formatRelativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHr = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  if (diffDay > 7) {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }
  if (diffDay > 0) return `${diffDay}d ago`;
  if (diffHr > 0) return `${diffHr}h ago`;
  if (diffMin > 0) return `${diffMin}m ago`;
  return "just now";
}

function EventIcon({ eventType }: { eventType: string }) {
  if (eventType === "detected") {
    return (
      <div className="w-2.5 h-2.5 rounded-full bg-accent shrink-0 mt-1" />
    );
  }
  if (eventType === "fixed") {
    return (
      <svg className="w-3.5 h-3.5 text-success shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
    );
  }
  if (eventType === "regression") {
    return (
      <svg className="w-3.5 h-3.5 text-danger shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
      </svg>
    );
  }
  if (eventType === "status_change") {
    return (
      <svg className="w-3.5 h-3.5 text-muted shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
      </svg>
    );
  }
  // note_added
  return (
    <svg className="w-3.5 h-3.5 text-muted shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z" />
    </svg>
  );
}

export function FindingTimeline({ events }: FindingTimelineProps) {
  const { t } = useTranslation();

  if (events.length === 0) {
    return (
      <p className="text-[12px] text-muted-light">{t("lineage.noLineage")}</p>
    );
  }

  return (
    <div className="space-y-0">
      {events.map((event, i) => {
        const isLast = i === events.length - 1;
        return (
          <div key={event.id} className="flex gap-3">
            {/* Timeline connector */}
            <div className="flex flex-col items-center">
              <div className="flex items-center justify-center w-6 h-6">
                <EventIcon eventType={event.event_type} />
              </div>
              {!isLast && <div className="w-px flex-1 min-h-3 bg-border" />}
            </div>
            {/* Content */}
            <div className="flex-1 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-[12px] font-medium text-foreground">
                  {t(`lineage.event_${event.event_type}`)}
                </span>
                <span className="text-[11px] text-muted-light">
                  {formatRelativeTime(event.created_at)}
                </span>
              </div>
              {event.event_type === "status_change" && event.old_status && event.new_status && (
                <p className="text-[11px] text-muted mt-0.5">
                  {event.old_status} &rarr; {event.new_status}
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
              {event.notes && (
                <p className="text-[11px] text-muted mt-1">{event.notes}</p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
