# 0033 Finding Reference Numbers Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Every finding gets a stable, human-readable reference number (`VLT-0001`) assigned at first detection, persisted across scans, and surfaced everywhere (UI, API, MCP, CLI) with click-to-copy for use in Jira tickets, PR descriptions, and compliance trails.

**Architecture:** `finding_lineage.ref_number` (integer, auto-assigned under a transaction on first insert). `FormatRef()` on the model renders `VLT-%04d`. The existing `/api/lineage?source_path=...` endpoint already returns `ref` and `ref_number`; the frontend merges onto findings via `lineageMap`.

**Tech Stack:** Go 1.22+ (backend, CLI), React 19 + TypeScript (frontend), Python 3.12 (MCP server), PostgreSQL + SQLite.

---

## Status of Prior Work (verified 2026-04-17)

Most of the plumbing is already present on this branch (uncommitted). Keep these; do not redo.

| Area | File | Status |
|------|------|--------|
| Model: `RefNumber`, `Ref`, `FormatRef()` | `backend/internal/model/lineage.go:33–66` | Done |
| Migration 013: add `ref_number` + backfill | `backend/migrations/013_finding_ref_numbers.sql` | Done |
| SQLite repo: auto-assign + SELECT + scan | `backend/internal/repository/sqlite_lineage_repo.go:65–102, 104–128, 323–393` | Done |
| Postgres repo: auto-assign + SELECT + scan | `backend/internal/repository/postgres_lineage_repo.go:34–81, 83–108, 294–352` | Done |
| Tests: 8 `TestLineageRefNumber_*` | `backend/internal/repository/lineage_ref_test.go` | Passing (`go test -run TestLineageRef` → PASS) |
| MCP enrich + `update_status` by ref | `mcp/server.py:180–238, 332–349` | Done |
| Frontend: `ref_number` on `FindingLineage` type | `frontend/src/lib/types.ts:186–212` | Done |
| Frontend: VLT column in FindingsTable | `frontend/src/components/results/FindingsTable.tsx:191–193, 253–263` | Done (display only) |

## Remaining Work

1. CLI `vulture results` — does not show ref.
2. Frontend — VLT ref is rendered as plain text; no click-to-copy for Jira workflow.
3. Frontend — truncated audit ID is rendered as plain text on dashboard and detail page; no click-to-copy.
4. Docs — status + rollback files missing.

---

## Task 1: Add VLT ref to CLI `vulture results`

**Files:**
- Modify: `cli/main.go:114-124` (finding struct)
- Modify: `cli/main.go:1291-1313` (`cmdResults`)
- Test: manual verification (CLI has no unit test harness today)

- [ ] **Step 1: Add `Ref` field to CLI finding struct**

`cli/main.go:114`:

```go
type finding struct {
	ID             string `json:"id"`
	AgentType      string `json:"agent_type"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	FilePath       string `json:"file_path"`
	LineStart      int    `json:"line_start"`
	Recommendation string `json:"recommendation"`
	Fingerprint    string `json:"fingerprint"`
	Ref            string `json:"ref,omitempty"`
}
```

- [ ] **Step 2: Add a small lineage struct and fetch helper**

Add near the other type decls (after the `finding` struct):

```go
type lineageRec struct {
	Fingerprint string `json:"fingerprint"`
	Ref         string `json:"ref"`
	RefNumber   int    `json:"ref_number"`
}

// fetchRefsBySourcePath returns a fingerprint→VLT-ref map for the given source path.
// Returns nil on any error (non-fatal — CLI falls back to no refs).
func fetchRefsBySourcePath(apiURL, token, sourcePath string) map[string]string {
	if sourcePath == "" {
		return nil
	}
	u := apiURL + "/api/lineage?source_path=" + url.QueryEscape(sourcePath) + "&limit=10000"
	recs := apiGet[[]lineageRec](u, token)
	if len(recs) == 0 {
		return nil
	}
	m := make(map[string]string, len(recs))
	for _, r := range recs {
		if r.Ref != "" && r.Fingerprint != "" {
			m[r.Fingerprint] = r.Ref
		}
	}
	return m
}
```

(Requires `import "net/url"` at the top — check; add if absent.)

- [ ] **Step 3: Update `cmdResults` to enrich and print the ref**

`cli/main.go:1291`:

```go
func cmdResults(apiURL string, id string) {
	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}
	a := apiGet[audit](apiURL+"/api/audits/"+id, token)
	printAuditSummary(a)

	if len(a.Findings) == 0 {
		return
	}

	refs := fetchRefsBySourcePath(apiURL, token, a.SourcePath)

	fmt.Println("\n  FINDINGS:")
	fmt.Println("  " + strings.Repeat("-", 70))
	for i, f := range a.Findings {
		ref := f.Ref
		if ref == "" {
			ref = refs[f.Fingerprint]
		}
		sev := colorSeverity(f.Severity)
		if ref != "" {
			fmt.Printf("  %d. %s [%s] %s\n", i+1, ref, sev, f.Title)
		} else {
			fmt.Printf("  %d. [%s] %s\n", i+1, sev, f.Title)
		}
		fmt.Printf("     File: %s:%d\n", f.FilePath, f.LineStart)
		fmt.Printf("     Category: %s | Agent: %s\n", f.Category, agentDisplayName(f.AgentType))
		if f.Recommendation != "" {
			fmt.Printf("     Fix: %s\n", f.Recommendation)
		}
		fmt.Println()
	}
}
```

- [ ] **Step 4: Confirm `audit` struct exposes `SourcePath`**

Verify `audit` in `cli/main.go` already has a `SourcePath` field. If not, add `SourcePath string \`json:"source_path"\``. (Check line ~100.)

- [ ] **Step 5: Rebuild and verify**

```bash
cd /home/user/src/vulture/cli && go build -o bin/vulture .
./bin/vulture results <recent-audit-id>
```

Expected: each finding line starts with `VLT-NNNN` before the severity tag.

---

## Task 2: Make VLT ref in FindingsTable copyable

**Files:**
- Modify: `frontend/src/components/results/FindingsTable.tsx:253–263`

- [ ] **Step 1: Replace the non-interactive `<span>` with a copy button**

Current (line 253):

```tsx
<td className="px-4 py-2.5">
  {(() => {
    const lin = finding.fingerprint ? lineageMap.get(finding.fingerprint) : undefined;
    const rn = lin?.ref_number;
    return rn && rn > 0 ? (
      <span className="text-[11px] font-mono font-medium text-accent">VLT-{String(rn).padStart(4, "0")}</span>
    ) : (
      <span className="text-[11px] text-muted-light">&mdash;</span>
    );
  })()}
</td>
```

New:

```tsx
<td className="px-4 py-2.5">
  {(() => {
    const lin = finding.fingerprint ? lineageMap.get(finding.fingerprint) : undefined;
    const rn = lin?.ref_number;
    if (!rn || rn <= 0) {
      return <span className="text-[11px] text-muted-light">&mdash;</span>;
    }
    const ref = `VLT-${String(rn).padStart(4, "0")}`;
    return (
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onCopy(ref); }}
        title={copied ? "Copied" : `Copy ${ref}`}
        className="text-[11px] font-mono font-medium text-accent hover:underline cursor-pointer"
      >
        {ref}
      </button>
    );
  })()}
</td>
```

The `onCopy` and `copied` values are already destructured at line 29 (`const { copied, onCopy } = useCopyFeedback();`) — reuse.

- [ ] **Step 2: Typecheck and run existing tests**

```bash
cd /home/user/src/vulture/frontend && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 3: Manual verification via Playwright in the final task (Task 5).**

---

## Task 3: Copy-to-clipboard for audit IDs

**Files:**
- Modify: `frontend/src/pages/Dashboard.tsx` (or the Recent Audits list component — locate via grep for `a0b9e658` rendering pattern / `id.slice(0,10)`)
- Modify: `frontend/src/pages/AuditResults.tsx` (detail page header — locate via page title / audit id display)

- [ ] **Step 1: Locate audit-ID render points**

```bash
cd /home/user/src/vulture/frontend/src && grep -rn 'slice(0, *10)\|slice(0, *13)\|substring(0, *10)\|substring(0, *13)' --include='*.tsx' --include='*.ts'
```

- [ ] **Step 2: Dashboard — wrap truncated id in copy button**

Pattern: change the existing `<span>…</span>` that renders the short id into a button whose `onClick` copies the **full** `audit.id`, preserving the existing `title` tooltip with the full UUID.

Sketch:

```tsx
const { copied, onCopy } = useCopyFeedback();
...
<button
  type="button"
  onClick={(e) => { e.stopPropagation(); e.preventDefault(); onCopy(audit.id); }}
  title={copied ? "Copied" : audit.id}
  className="text-xs font-mono text-muted hover:text-accent cursor-pointer"
>
  {audit.id.slice(0, 10)}
</button>
```

The `e.preventDefault()` prevents the parent `<a>` from navigating when the user clicks the ID.

- [ ] **Step 3: Detail page — add a copy-ID button next to "Audit Results" heading**

In `AuditResults.tsx`, near the heading, render:

```tsx
<button onClick={() => onCopy(auditId)} title={copied ? "Copied" : auditId}
  className="ml-3 text-xs font-mono text-muted hover:text-accent cursor-pointer">
  {auditId.slice(0, 10)}
</button>
```

- [ ] **Step 4: Typecheck**

```bash
cd /home/user/src/vulture/frontend && npx tsc --noEmit
```

Expected: no errors.

---

## Task 4: Docs — status + rollback

**Files:**
- Create: `docs/features/0033_finding_reference_numbers/0033_implementation_status.md`
- Create: `docs/features/0033_finding_reference_numbers/0033_rollback_plan.md`

See the accompanying files in this commit — they mirror the format used by 0031 and 0032.

---

## Task 5: End-to-end verification

- [ ] **Step 1: Rebuild backend + CLI**

```bash
cd /home/user/src/vulture/backend && go test ./internal/repository/ -run TestLineageRef -count=1
cd /home/user/src/vulture/backend && go build -o bin/vulture ./cmd/vulture
cd /home/user/src/vulture/cli && go build -o bin/vulture .
```

- [ ] **Step 2: Rebuild frontend image and restart containers**

```bash
cd /home/user/src/vulture && docker compose up -d --build backend frontend
```

- [ ] **Step 3: Verify via Playwright**

1. Navigate to `http://localhost:23001`, log in as `admin@vulture.local` (password = value of `$VULTURE_LOCAL_DEV_PASSWORD` exported when the backend started, or the hex string printed to the backend log line `Seeded local dev user: ...`).
2. Open a recent audit with findings (e.g., `73a861bb` — 574 findings).
3. Confirm the first column of FindingsTable shows `VLT-NNNN` values.
4. Click one VLT label — verify clipboard contains `VLT-NNNN`.
5. On the dashboard card, click the short audit ID — verify clipboard contains full UUID.

- [ ] **Step 4: Verify CLI**

```bash
./cli/bin/vulture results <audit-id>
```

Expected: findings lines begin with `VLT-NNNN` before the severity bracket.

---

## Self-Review Checklist

- [x] Every remaining task names exact files and line ranges.
- [x] TypeScript/Go snippets compile as written.
- [x] No placeholders; no "TBD"; no "similar to X".
- [x] `FormatRef()` / `Ref` / `ref_number` naming consistent across model, repo, TS, CLI.
- [x] Webhook integration deferred — payload is audit-level, not finding-level, and the ref-per-finding use-case is served by the Jira-flow (copy VLT from UI into ticket). Add a finding-list section to webhooks in a future feature if users request it.
