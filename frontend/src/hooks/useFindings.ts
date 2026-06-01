import { useMemo, useState } from "react";
import { SEVERITY_ORDER } from "@/lib/constants.ts";
import type { Finding, Severity } from "@/lib/types.ts";

type SortField = "severity" | "category" | "file" | "title" | "agent_type";
type SortDirection = "asc" | "desc";

const PAGE_SIZE = 25;

// useFindings filters + sorts + paginates the findings table.
//
// `falsePositiveFingerprints` is the set of fingerprints whose lineage
// current_status is "false_positive" (manual triage). Combined with
// each finding's own validation_status === "likely_fp" (automatic
// L1-L5 verdict), it drives the opt-in "hide false positives" toggle.
// The toggle defaults OFF so nothing disappears without an explicit
// user action (compliance-safe).
export function useFindings(
  allFindings: Finding[],
  falsePositiveFingerprints?: Set<string>,
) {
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">("all");
  const [filterAgent, setFilterAgent] = useState<string>("all");
  const [hideFalsePositives, setHideFalsePositives] = useState(false);
  const [page, setPage] = useState(0);

  // A finding is a false positive if EITHER signal fires:
  //   - automatic: validation_status === "likely_fp"
  //   - manual: its fingerprint is in the triaged-FP set
  const isFalsePositive = (f: Finding): boolean =>
    f.validation_status === "likely_fp" ||
    (!!f.fingerprint && !!falsePositiveFingerprints?.has(f.fingerprint));

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
    setPage(0);
  };

  const setFilterSeverityAndReset = (sev: Severity | "all") => {
    setFilterSeverity(sev);
    setPage(0);
  };

  const setFilterAgentAndReset = (agent: string) => {
    setFilterAgent(agent);
    setPage(0);
  };

  const setHideFalsePositivesAndReset = (hide: boolean) => {
    setHideFalsePositives(hide);
    setPage(0);
  };

  // Total FP count across the whole audit (union of both signals),
  // independent of the active severity/agent filters or the toggle —
  // this is what the "Hide false positives (N)" label shows.
  const falsePositiveCount = useMemo(
    () => allFindings.filter(isFalsePositive).length,
    // isFalsePositive closes over falsePositiveFingerprints.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [allFindings, falsePositiveFingerprints],
  );

  const sorted = useMemo(() => {
    let filtered = allFindings;

    if (filterSeverity !== "all") {
      filtered = filtered.filter((f) => f.severity === filterSeverity);
    }
    if (filterAgent !== "all") {
      filtered = filtered.filter((f) => (f.agent_type ?? f.agent_id) === filterAgent);
    }
    if (hideFalsePositives) {
      filtered = filtered.filter((f) => !isFalsePositive(f));
    }

    return [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case "severity":
          cmp = (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
          break;
        case "category":
          cmp = a.category.localeCompare(b.category);
          break;
        case "file":
          cmp = a.file_path.localeCompare(b.file_path);
          break;
        case "title":
          cmp = a.title.localeCompare(b.title);
          break;
        case "agent_type":
          cmp = (a.agent_type ?? a.agent_id ?? "").localeCompare(b.agent_type ?? b.agent_id ?? "");
          break;
      }
      return sortDirection === "asc" ? cmp : -cmp;
    });
    // isFalsePositive closes over falsePositiveFingerprints.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allFindings, filterSeverity, filterAgent, hideFalsePositives, falsePositiveFingerprints, sortField, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const findings = sorted.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  return {
    findings,
    totalFiltered: sorted.length,
    page: safePage,
    totalPages,
    setPage,
    sortField,
    sortDirection,
    filterSeverity,
    filterAgent,
    hideFalsePositives,
    falsePositiveCount,
    setFilterSeverity: setFilterSeverityAndReset,
    setFilterAgent: setFilterAgentAndReset,
    setHideFalsePositives: setHideFalsePositivesAndReset,
    toggleSort,
  };
}
