import { describe, expect, it } from "vitest";
import { eventNoteText, indexLineage, lastEventOutcome, reasonText, resolveLineage } from "./lineage.ts";

// The global test setup stubs react-i18next's `t` to echo its key, so these
// assertions are about WHICH key is chosen and whether anything is chosen at
// all — the two decisions this module makes.
const t = ((key: string, opts?: Record<string, unknown>) =>
  opts && "detail" in opts ? `${key}:${String(opts.detail)}` : key) as never;

describe("reasonText", () => {
  // Every string here is produced verbatim today: the first four by
  // backend/internal/service/lineage_scan_pass.go, the rest by
  // agents/shared/shared/lineage_checks.py. Before this mapping each of them
  // reached the page as prose, untranslated, in all six locales.
  it.each([
    ["scan truncated: enumerated set is partial", "lineage.reason_truncated"],
    ["file_path is absolute and not under the scanned root", "lineage.reason_other_mount"],
    ["path is outside the scanned sub-tree", "lineage.reason_outside"],
    ["agent did not report result_schema >= 2", "lineage.reason_no_protocol"],
    ["missing", "lineage.reason_not_checked"],
    ["no_quote", "lineage.reason_no_quote"],
    ["file_missing", "lineage.reason_file_missing"],
    // The three refusals the checker answers instead of `gone` when the
    // citation is not a readable in-tree file.
    ["not_a_file", "lineage.reason_not_a_file"],
    ["no_path", "lineage.reason_no_path"],
    ["outside_root", "lineage.reason_outside_root"],
    ["evidence_returned", "lineage.reason_returned"],
    ["ambiguous", "lineage.reason_ambiguous"],
    ["near_miss", "lineage.reason_near_miss"],
    ["found_elsewhere", "lineage.reason_found_elsewhere"],
    ["absent", "lineage.reason_absent"],
    ["line_too_long", "lineage.reason_unquoted"],
    ["exact", "lineage.reason_exact"],
  ])("translates %s", (raw, key) => {
    expect(reasonText(raw, t)).toBe(key);
  });

  it("carries the pruned directory into the sentence", () => {
    expect(reasonText("path is under pruned prefix .vscode", t)).toBe(
      "lineage.reason_pruned:.vscode",
    );
  });

  it.each([
    ["oversize:531002>524288", "lineage.reason_oversize"],
    ["unreadable:PermissionError", "lineage.reason_unreadable"],
    ["error:ValueError", "lineage.reason_error"],
  ])("strips the machine tail of %s", (raw, key) => {
    expect(reasonText(raw, t)?.startsWith(key)).toBe(true);
  });

  it("says nothing rather than printing a token it does not know", () => {
    expect(reasonText("some_future_token", t)).toBeNull();
    expect(reasonText("", t)).toBeNull();
    expect(reasonText(undefined, t)).toBeNull();
  });
});

describe("eventNoteText", () => {
  it("leaves a note a person typed exactly as typed", () => {
    expect(eventNoteText("note_added", "waiting on the vendor", t)).toBe("waiting on the vendor");
    expect(eventNoteText("status_change", "accepted for this release", t)).toBe(
      "accepted for this release",
    );
  });

  it("translates a note the scanner wrote", () => {
    expect(eventNoteText("scope_unknown", "agent did not report result_schema >= 2", t)).toBe(
      "lineage.reason_no_protocol",
    );
  });

  it("drops a scanner note it cannot translate", () => {
    expect(eventNoteText("out_of_scope", "brand_new_reason", t)).toBeNull();
  });
});

describe("lastEventOutcome", () => {
  // Mirrors model.EvidenceOutcomes in backend/internal/model/target.go.
  it.each([
    ["confirmed_by_evidence", "confirmed"],
    ["evidence_gone", "gone"],
    ["unconfirmable", "unconfirmable"],
    ["out_of_scope", "out_of_scope"],
    ["skipped_degraded", "skipped_degraded"],
    ["absent_in_result", "absent_in_result"],
    ["scope_unknown", "scope_unknown"],
    // A re-find IS an observation — the most common one. Without it the label
    // under a re-found row keeps saying what the previous scan saw.
    ["reported", "reported"],
  ])("%s is an observation", (event, outcome) => {
    expect(lastEventOutcome(event)).toBe(outcome);
  });

  it.each(["detected", "status_change", "note_added", "memory_synced", "merged", "", undefined])(
    "%s is not an observation",
    (event) => {
      expect(lastEventOutcome(event)).toBeNull();
    },
  );
});

describe("resolveLineage", () => {
  const row = (id: string, agent: string, fingerprint: string, fingerprint_v2?: string) =>
    ({ id, agent_type: agent, fingerprint, fingerprint_v2, current_status: "open" }) as never;

  it("prefers fingerprint_v2 within the agent type, as the lineage writer does", () => {
    const index = indexLineage([row("by-v1", "owasp", "v1-a"), row("by-v2", "owasp", "v1-old", "v2-a")]);
    expect(resolveLineage(index, { agent_type: "owasp", fingerprint: "v1-a", fingerprint_v2: "v2-a" })?.id).toBe("by-v2");
  });

  it("falls back to the v1 fingerprint for a row with no v2", () => {
    const index = indexLineage([row("legacy", "cwe", "v1-legacy")]);
    expect(resolveLineage(index, { agent_type: "cwe", fingerprint: "v1-legacy", fingerprint_v2: "v2-new" })?.id).toBe("legacy");
  });

  it("never crosses agent types", () => {
    const index = indexLineage([row("owasp-row", "owasp", "v1-x", "v2-x")]);
    expect(resolveLineage(index, { agent_type: "cwe", fingerprint: "v1-y", fingerprint_v2: "v2-x" })).toBeUndefined();
    expect(resolveLineage(index, { agent_type: "cwe", fingerprint: "v1-x" })).toBeUndefined();
  });

  it("reads agent_id when agent_type is absent, case-insensitively", () => {
    const index = indexLineage([row("r", "owasp", "v1", "v2")]);
    expect(resolveLineage(index, { agent_id: "OWASP", fingerprint: "nope", fingerprint_v2: "v2" })?.id).toBe("r");
  });

  it("matches on v1 alone when the caller knows no agent", () => {
    const index = indexLineage([row("r", "cwe", "v1-only")]);
    expect(resolveLineage(index, { fingerprint: "v1-only" })?.id).toBe("r");
  });

  it("keeps the first row for a duplicated key (rows arrive newest first)", () => {
    const index = indexLineage([row("newest", "cwe", "dup", "v2-dup"), row("older", "cwe", "dup", "v2-dup")]);
    expect(resolveLineage(index, { agent_type: "cwe", fingerprint: "dup", fingerprint_v2: "v2-dup" })?.id).toBe("newest");
  });

  it("returns undefined for an item with no fingerprints", () => {
    expect(resolveLineage(indexLineage([row("r", "cwe", "v1")]), { agent_type: "cwe" })).toBeUndefined();
  });
});
