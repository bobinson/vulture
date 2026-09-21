//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 P2 / scenario S15 — a directory the walker refused to enter is
// OUT OF SCOPE, never repaired.
//
// THE DEFECT THIS PINS. `.vscode`, `.idea`, `.eclipse` and `.claude` are in the
// scanner's hardcoded SKIP_DIRS, so a root scan never descends into them.
// Feature 0091 P2 (D2) un-prunes the well-known autorun files inside them, and
// `VULTURE_SCAN_EDITOR_CONFIG=false` is that change's rollback: with it set the
// editor directories are pruned in full again, exactly as they are today.
//
// Under rollback the scan looks at nothing in `.vscode`. Its silence about a
// finding there is worth nothing, and the whole reason the scope check exists
// is that this silence is otherwise indistinguishable from repair. Before
// feature 0091 it only failed to bite because a scan of `.vscode` and a scan of
// the project root landed in SEPARATE lineage partitions keyed on the exact
// `source_path` string; once P3 unifies them under one target, the root scan's
// silence reaches the row the `.vscode`-rooted scan created, and this check is
// the only thing standing between that row and a false `fixed`.
//
// A false `fixed` here is not cosmetic. It closes the row, the memory sync then
// marks the memory `resolved`, the finding leaves the prior-findings block, and
// the malicious folder-open task — the highest-severity thing a repository can
// carry — is reported as remediated while it sits in the file untouched. Seven
// live lineage rows under a `.vscode` directory are `open` today and are
// exactly the rows this decides the fate of.
//
// THE PATH FORM IS THE POINT. `pruned_dirs` is root-relative by contract (the
// agent cannot send a host path the backend can join), but a lineage row's
// `file_path` is whatever the agent put on the finding, and agents emit
// ABSOLUTE paths: 8,254 of the 10,663 persisted rows begin with `/`, including
// every `.vscode` row. A scope check that compares the two without resolving
// the row's path against the scanned root sees `home/user/proj/.vscode/tasks.
// json` against the prefix `.vscode`, finds no match, calls the row in scope,
// and — for the deterministic tier, whose absence rule 0091 deliberately leaves
// alone — marks it FIXED. Both path forms occur in the live table (8,254
// absolute, 2,409 relative), so both are subtests here and neither is the
// "normal" one.
//
// THE CONTRACT. A lineage row whose file lies under a prefix the agent reported
// in `pruned_dirs` — expressed in EITHER path form — is recorded
// `out_of_scope` and left exactly as it was: same status, same seen_count (the
// scan did not observe it either), and no closure event on its timeline. The
// tier is irrelevant: the rows below are DELIBERATELY deterministic, because
// "we did not look" outranks "a skill would have found it".
//
// The last subtest is the discriminator: the same row, the same silence, but a
// scan that DID walk the directory closes it. Without that control this test
// would also pass on an implementation that simply stopped closing anything.

// editorConfigLineageFinding is a deterministic finding at the reference
// incident's site — the folder-open shell task at `.vscode/tasks.json:7` —
// carrying whatever path form the caller says the agent emitted.
func editorConfigLineageFinding(fingerprint, filePath string) model.Finding {
	f := lineageTestFinding(fingerprint)
	f.Provenance = "skill"
	f.Title = "Task runs a shell command on folder open"
	f.Category = "CWE-506"
	f.FilePath = filePath
	f.LineStart = 7
	f.LineEnd = 7
	return f
}

// prunedEditorDirResult is the result of a scan run with
// VULTURE_SCAN_EDITOR_CONFIG=false: the agent speaks the 0091 protocol, reports
// the editor directories it refused to descend into, and reports no finding
// from either of them.
func prunedEditorDirResult() *model.ScanResult {
	return &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{".idea", ".vscode"},
		Findings:     []model.Finding{unrelatedFinding()},
	}
}

func TestPrunedDirIsOutOfScopeNotFixed(t *testing.T) {
	// The two path forms a lineage row's file_path is actually stored in. The
	// absolute form is what agents emit today and what 77% of the live table
	// holds; the relative form is what the older rows carry.
	pathForms := map[string]func(root string) string{
		"absolute_path_as_agents_emit_it": func(root string) string {
			return filepath.Join(root, ".vscode", "tasks.json")
		},
		"root_relative_path": func(_ string) string {
			return ".vscode/tasks.json"
		},
	}

	for name, pathOf := range pathForms {
		t.Run(name, func(t *testing.T) {
			// The scenario is an agent that pruned the editor directory whole
			// and said so. The backend never inspects scanner configuration —
			// the agent's `pruned_dirs` is the entire wire contract — so this
			// result is constructed directly rather than provoked.

			svc, repo := newLineageStack(t)
			srcPath := t.TempDir()
			source := lineageTestSource(srcPath)
			fp := "fp-vscode-autorun-" + name

			if err := svc.ProcessAuditFindings(lineageTestAudit("audit-0091-s15-1"), source,
				[]model.Finding{editorConfigLineageFinding(fp, pathOf(srcPath))}); err != nil {
				t.Fatalf("seed scan: %v", err)
			}
			before := lineageRowOf(t, repo, fp, srcPath)
			if before.CurrentStatus != model.LineageStatusOpen {
				t.Fatalf("after the seed scan the row must be %q, got %q",
					model.LineageStatusOpen, before.CurrentStatus)
			}

			if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-s15-2"), source, "cwe",
				prunedEditorDirResult()); err != nil {
				t.Fatalf("record scan outcome: %v", err)
			}

			after := lineageRowOf(t, repo, fp, srcPath)
			if after.CurrentStatus == model.LineageStatusFixed {
				t.Fatalf("a scan that never entered .vscode must not close a finding "+
					"inside it: the row at %q was marked %q while its code was never "+
					"read. pruned_dirs was %v",
					before.FilePath, model.LineageStatusFixed, prunedEditorDirResult().PrunedDirs)
			}
			if after.CurrentStatus != before.CurrentStatus {
				t.Fatalf("an out-of-scope row is left exactly as it was: status %q -> %q",
					before.CurrentStatus, after.CurrentStatus)
			}
			if after.SeenCount != before.SeenCount {
				t.Fatalf("a scan that did not look at the path did not observe the "+
					"finding either: seen_count %d -> %d", before.SeenCount, after.SeenCount)
			}

			types := eventTypesOf(t, repo, after.ID)
			if !hasEventType(types, model.LineageEventOutOfScope) {
				t.Fatalf("expected an %q event recording that the scan could not have "+
					"seen %q, so a reader can tell \"never looked at\" from \"looked at "+
					"and gone\", got %v",
					model.LineageEventOutOfScope, before.FilePath, types)
			}
			for _, forbidden := range []model.LineageEventType{
				model.LineageEventFixed,
				model.LineageEventEvidenceGone,
			} {
				if hasEventType(types, forbidden) {
					t.Fatalf("a pruned path produces no closure of any kind, but a %q "+
						"event was recorded: %v", forbidden, types)
				}
			}
		})
	}

	t.Run("scanned_dir_still_closes", func(t *testing.T) {
		// The discriminator. Same row, same silence — but this agent walked the
		// directory, so its silence IS evidence for the deterministic tier and
		// the row must close exactly as it does today. An implementation that
		// merely stopped closing rows would pass the subtests above and fail
		// here.
		svc, repo := newLineageStack(t)
		srcPath := t.TempDir()
		source := lineageTestSource(srcPath)
		const fp = "fp-vscode-autorun-scanned"

		if err := svc.ProcessAuditFindings(lineageTestAudit("audit-0091-s15-3"), source,
			[]model.Finding{editorConfigLineageFinding(fp,
				filepath.Join(srcPath, ".vscode", "tasks.json"))}); err != nil {
			t.Fatalf("seed scan: %v", err)
		}

		scanned := &model.ScanResult{
			ResultSchema: model.ScanResultSchemaEvidence,
			PrunedDirs:   []string{},
			Findings:     []model.Finding{unrelatedFinding()},
		}
		if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-s15-4"), source, "cwe",
			scanned); err != nil {
			t.Fatalf("record scan outcome: %v", err)
		}

		if got := statusOf(t, repo, fp, srcPath); got != model.LineageStatusFixed {
			t.Fatalf("a deterministic row whose directory WAS walked still closes on "+
				"absence: expected %q, got %q", model.LineageStatusFixed, got)
		}
	})
}
