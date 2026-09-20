package migrations

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/pathutil"
)

// Feature 0091 §7.1. Migration 027's step-4 backfill hardcodes the run-mode
// prefixes in SQL, because a migration cannot call Go. That makes it the one
// place a SECOND copy of the prefix table exists — and the whole premise of
// target identity is that there is exactly one answer to "which prefixes are
// deployment artefacts rather than part of the codebase's name".
//
// A drift here is silent and expensive: a prefix known to the scanner but not
// to the backfill leaves every historical row under it keyed by its mount, so
// the histories the migration exists to reunite stay split, and the unique
// index in step 6 happily accepts the duplicates.
func TestRunModeRootsMatchMigration027(t *testing.T) {
	// os.TempDir() follows TMPDIR, so the git-ingest root is host-dependent.
	// The SQL can only know the conventional location; pin it so the two sides
	// are comparable at all.
	t.Setenv("TMPDIR", "/tmp")

	body, err := sqlFS.ReadFile("027_lineage_target_identity.sql")
	if err != nil {
		t.Fatalf("read 027: %v", err)
	}
	sql := string(body)

	roots := pathutil.RunModeRoots()
	if len(roots) == 0 {
		t.Fatal("pathutil.RunModeRoots() is empty; the run-mode strip would be a no-op")
	}
	for _, root := range roots {
		if !strings.Contains(sql, "'"+root+"'") {
			t.Errorf("run-mode root %q is stripped by the scanner but not by migration 027's "+
				"step-4 backfill: every historical row under it keeps a mount-specific target "+
				"key, so its history stays split. Add it to the ARRAY[...] in "+
				"vlt_0091_strip_runmode()", root)
		}
	}

	// And the reverse: a prefix the SQL strips but Go does not would make the
	// backfill disagree with every scan that follows it.
	for _, quoted := range sqlStrippedPrefixes(sql) {
		if !containsRoot(roots, quoted) {
			t.Errorf("migration 027 strips %q but pathutil.RunModeRoots() does not, so the "+
				"backfill and every later scan would key the same tree differently", quoted)
		}
	}
}

// sqlStrippedPrefixes pulls the literals out of the FOREACH array in
// vlt_0091_strip_runmode. Deliberately narrow: it reads the one line that
// declares the table rather than every quoted string in the file.
func sqlStrippedPrefixes(sql string) []string {
	const marker = "FOREACH pre IN ARRAY ARRAY["
	i := strings.Index(sql, marker)
	if i < 0 {
		return nil
	}
	rest := sql[i+len(marker):]
	j := strings.Index(rest, "]")
	if j < 0 {
		return nil
	}
	var out []string
	for _, part := range strings.Split(rest[:j], ",") {
		if v := strings.Trim(strings.TrimSpace(part), "'"); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func containsRoot(roots []string, want string) bool {
	for _, r := range roots {
		if r == want {
			return true
		}
	}
	return false
}
