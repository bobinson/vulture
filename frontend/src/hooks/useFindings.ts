import { useMemo, useState } from "react";
import { SEVERITY_ORDER } from "@/lib/constants.ts";
import type { Finding, Severity } from "@/lib/types.ts";

type SortField = "severity" | "category" | "file" | "title";
type SortDirection = "asc" | "desc";

const PAGE_SIZE = 25;

export function useFindings(allFindings: Finding[]) {
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">("all");
  const [filterAgent, setFilterAgent] = useState<string>("all");
  const [page, setPage] = useState(0);

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

  const sorted = useMemo(() => {
    let filtered = allFindings;

    if (filterSeverity !== "all") {
      filtered = filtered.filter((f) => f.severity === filterSeverity);
    }
    if (filterAgent !== "all") {
      filtered = filtered.filter((f) => f.agent_id === filterAgent);
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
      }
      return sortDirection === "asc" ? cmp : -cmp;
    });
  }, [allFindings, filterSeverity, filterAgent, sortField, sortDirection]);

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
    setFilterSeverity: setFilterSeverityAndReset,
    setFilterAgent: setFilterAgentAndReset,
    toggleSort,
  };
}
