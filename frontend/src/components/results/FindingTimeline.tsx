import { LineageTimeline } from "./LineageTimeline.tsx";
import type { LineageEvent } from "@/lib/types.ts";

interface FindingTimelineProps {
  events: LineageEvent[];
}

/**
 * The inline timeline of one row of the findings table.
 *
 * Same renderer as the lineage detail page (one event vocabulary, one set of
 * tones) with the per-occurrence scan links off: the row it expands from is
 * already scoped to one scan, and a link out of a table row that the user is
 * mid-way through reading is a trap rather than a shortcut.
 */
export function FindingTimeline({ events }: FindingTimelineProps) {
  return <LineageTimeline events={events} linkToScans={false} />;
}
