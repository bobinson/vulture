package repo

import (
	"database/sql"
	"fmt"
)

type Evidence struct {
	FileHash      string
	IncrementSeen bool
	UpdateWindow  bool
	LineStart     int
	LineEnd       int
}

func applyEvidence(db *sql.DB, id string, ev Evidence) error {
	sets := "evidence_file_hash = $1, updated_at = now()"
	args := []interface{}{ev.FileHash}
	if ev.IncrementSeen {
		sets += ", seen_count = COALESCE(seen_count, 1) + 1"
	}
	if ev.UpdateWindow {
		sets += fmt.Sprintf(", evidence_line_start = $%d, evidence_line_end = $%d", len(args)+1, len(args)+2)
		args = append(args, ev.LineStart, ev.LineEnd)
	}
	args = append(args, id)
	q := fmt.Sprintf(`UPDATE finding_lineage SET %s WHERE id = $%d`, sets, len(args)) // EXPECT: clean
	_, err := db.Exec(q, args...)
	return err
}
