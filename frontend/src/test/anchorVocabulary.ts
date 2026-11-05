import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Feature 0074 #20 — the anchor verifier's vocabulary as the agent exports it
// (pinned to agents/shared/shared/anchor.py by the Python suite). Tests read
// it from here instead of redeclaring the literals.
export interface AnchorVocabulary {
  check_id: string;
  statuses: string[];
  claimed_line_ranges: string[];
  duplicate_rule: string;
}

export const ANCHOR_VOCABULARY = JSON.parse(
  readFileSync(resolve(__dirname, "../../../agents/shared/tests/contract/anchor_vocabulary_0074.json"), "utf8"),
) as AnchorVocabulary;
