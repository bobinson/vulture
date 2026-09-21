import type { TFunction } from "i18next";
import type { FindingLineage, LineageEvent, LineageEvidence } from "./types.ts";

interface WrappedLineageDetail {
  lineage: FindingLineage;
  events?: LineageEvent[];
  evidence?: LineageEvidence | null;
  seen_in?: string[];
}

function isWrapped(payload: unknown): payload is WrappedLineageDetail {
  return (
    typeof payload === "object" &&
    payload !== null &&
    typeof (payload as { lineage?: unknown }).lineage === "object" &&
    (payload as { lineage?: unknown }).lineage !== null
  );
}

/**
 * Flatten `GET /api/lineage/{id}` into one `FindingLineage`.
 *
 * The endpoint answers `{ lineage, events, evidence, seen_in }` — the row and
 * the things computed alongside it are separate keys on the wire. The UI wants
 * one object, and the pre-0091 shape (`{ lineage, events }`) has to keep
 * working, as does a flat row from any caller that already merged them. Doing
 * the merge in ONE place means no component has to know which shape it got.
 */
export function normalizeLineageDetail(payload: unknown): FindingLineage {
  if (!isWrapped(payload)) return payload as FindingLineage;
  return {
    ...payload.lineage,
    events: payload.events ?? payload.lineage.events ?? [],
    evidence: payload.evidence ?? payload.lineage.evidence,
    seen_in: payload.seen_in ?? payload.lineage.seen_in,
  };
}

/**
 * The events whose `notes` are written by the SCANNER, not by a person.
 *
 * The distinction is load-bearing. `status_change` and `note_added` carry text
 * a human typed into the notes field and must reach the page byte for byte;
 * every event below carries a machine token the scan pass wrote
 * (`lineage_scan_pass.go`) or the agent's checker returned
 * (`agents/shared/shared/lineage_checks.py`), and those were rendering raw:
 * a reader was shown "agent did not report result_schema >= 2",
 * "file_path is absolute and not under the scanned root" and
 * "oversize:531002>524288" as though they were prose, in English, in all six
 * locales.
 */
const MACHINE_NOTE_EVENTS: ReadonlySet<string> = new Set([
  "out_of_scope",
  "scope_unknown",
  "skipped_degraded",
  "unconfirmable",
  "confirmed_by_evidence",
  "evidence_gone",
  "regression",
  "fixed",
  "reported",
]);

/** Machine reasons carrying a variable tail, longest prefix first. */
const REASON_PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ["path is under pruned prefix ", "lineage.reason_pruned"],
  ["oversize:", "lineage.reason_oversize"],
  ["unreadable:", "lineage.reason_unreadable"],
  ["error:", "lineage.reason_error"],
];

/**
 * Whole-value machine reasons. The Go set comes from `lineage_scan_pass.go`
 * (the four scope reasons, the missing-check marker, the regression marker);
 * the rest are the checker's outcome/reason tokens and the 0076 anchor
 * statuses they pass through.
 */
const REASON_KEYS: Readonly<Record<string, string>> = {
  "scan truncated: enumerated set is partial": "lineage.reason_truncated",
  "file_path is absolute and not under the scanned root": "lineage.reason_other_mount",
  "path is outside the scanned sub-tree": "lineage.reason_outside",
  "agent did not report result_schema >= 2": "lineage.reason_no_protocol",
  missing: "lineage.reason_not_checked",
  no_quote: "lineage.reason_no_quote",
  file_missing: "lineage.reason_file_missing",
  // The checker refuses a citation it cannot read as a file, or one that
  // escapes the scanned root, rather than reading its silence as repair.
  not_a_file: "lineage.reason_not_a_file",
  no_path: "lineage.reason_no_path",
  outside_root: "lineage.reason_outside_root",
  unreadable: "lineage.reason_unreadable",
  oversize: "lineage.reason_oversize",
  evidence_returned: "lineage.reason_returned",
  ambiguous: "lineage.reason_ambiguous",
  near_miss: "lineage.reason_near_miss",
  found_elsewhere: "lineage.reason_found_elsewhere",
  absent: "lineage.reason_absent",
  unquoted: "lineage.reason_unquoted",
  line_too_long: "lineage.reason_unquoted",
  exact: "lineage.reason_exact",
  confirmed: "lineage.reason_exact",
  reanchored: "lineage.reason_found_elsewhere",
  gone: "lineage.reason_file_gone",
  unconfirmable: "lineage.reason_unknown",
};

/**
 * A scanner reason as a sentence a person can act on, or `null`.
 *
 * `null` means "say nothing here" — deliberately, and only for a token this
 * build has never heard of. A newer backend inventing a reason must not put
 * its internal vocabulary on the page; the caller keeps the raw value on the
 * element's `title` so it stays inspectable without being read out as prose.
 */
export function reasonText(raw: string | undefined, t: TFunction): string | null {
  const value = (raw ?? "").trim();
  if (value === "") return null;
  const key = REASON_KEYS[value];
  if (key) return t(key);
  for (const [prefix, prefixKey] of REASON_PREFIXES) {
    if (value.startsWith(prefix)) {
      return t(prefixKey, { detail: value.slice(prefix.length) });
    }
  }
  return null;
}

/**
 * The note to render under one timeline event, and whether it is prose a
 * person wrote.
 *
 * A human note is shown verbatim; a scanner note is translated, or dropped
 * when this build cannot translate it.
 */
export function eventNoteText(
  eventType: string,
  notes: string | undefined,
  t: TFunction,
): string | null {
  if (!notes) return null;
  if (!MACHINE_NOTE_EVENTS.has(eventType)) return notes;
  return reasonText(notes, t);
}

/**
 * The last evidence observation behind an aggregate row, as one of the
 * `lineage.evidence_*` phrases the detail page already uses.
 *
 * Mirrors `model.EvidenceOutcomes` (Go). Any other event type — `detected`,
 * `status_change`, `note_added`, `memory_synced`, `merged` — is not an
 * observation and answers `null`: the status chip has already said everything
 * such a row has to say.
 */
const OUTCOME_BY_EVENT: Readonly<Record<string, string>> = {
  confirmed_by_evidence: "confirmed",
  evidence_gone: "gone",
  unconfirmable: "unconfirmable",
  out_of_scope: "out_of_scope",
  skipped_degraded: "skipped_degraded",
  absent_in_result: "absent_in_result",
  scope_unknown: "scope_unknown",
  // The scan reported the finding again. The most common observation, and
  // the one whose absence left the previous scan's label standing.
  reported: "reported",
};

export function lastEventOutcome(eventType: string | undefined): string | null {
  return OUTCOME_BY_EVENT[(eventType ?? "").trim()] ?? null;
}
