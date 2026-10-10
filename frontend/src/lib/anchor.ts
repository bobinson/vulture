import type { ChipTone } from "@/components/shared/Chip.tsx";

// Feature 0074 — the anchor verifier's wire vocabulary as the UI reads it.
// The source of truth is agents/shared/shared/anchor.py, exported to
// agents/shared/tests/contract/anchor_vocabulary_0074.json; anchor.test.ts
// pins these to that file, so a status or range added on the agent side
// fails here instead of rendering untoned.

/** validation.checks[].id of the quote verifier's check. */
export const ANCHOR_CHECK_ID = "anchor";

/** Tone per status; a status absent here (unquoted, unreadable, oversize) is neutral. */
export const ANCHOR_STATUS_TONES: Readonly<Record<string, ChipTone>> = {
  exact: "success",
  reanchored: "info",
  ambiguous: "warning",
  near_miss: "warning",
  found_elsewhere: "warning",
  absent: "danger",
};

/** Tone per claimed_line_range; every range is listed. */
export const ANCHOR_RANGE_TONES: Readonly<Record<string, ChipTone>> = {
  in_file: "neutral",
  past_eof: "warning",
  no_line: "neutral",
};
