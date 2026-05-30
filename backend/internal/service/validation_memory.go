// Package service — validation_memory.go
//
// L4 memory_prior (feature 0045) — minimal v1 implementation.
//
// For each finding, look up an exact-fingerprint match in
// audit_memories.user_label and inherit a memory check accordingly.
// Embedding-based kNN is deferred to a follow-up; this exact-match
// path covers the common "I labelled this exact finding before" case
// which is what the thumbs-up/down UI produces.

package service

import (
	"context"
	"database/sql"
	"log"
)

// MemoryPriorLookup queries audit_memories.user_label by fingerprint
// for a batch of fingerprints in one round-trip. Returns a map from
// fingerprint to label ("fp" | "tp"). Fingerprints with no label are
// absent from the result.
type MemoryPriorLookup struct {
	db      *sql.DB
	dialect string
}

func NewMemoryPriorLookup(db *sql.DB, dialect string) *MemoryPriorLookup {
	return &MemoryPriorLookup{db: db, dialect: dialect}
}

// LookupLabels batch-loads labels for `fingerprints`. The query uses
// a single IN clause; safe for batch sizes up to a few thousand.
func (m *MemoryPriorLookup) LookupLabels(
	ctx context.Context, fingerprints []string,
) (map[string]string, error) {
	if len(fingerprints) == 0 {
		return map[string]string{}, nil
	}
	// Build the IN clause manually (database/sql doesn't expand slices).
	placeholders := make([]byte, 0, len(fingerprints)*3)
	args := make([]interface{}, 0, len(fingerprints))
	for i, fp := range fingerprints {
		if i > 0 {
			placeholders = append(placeholders, ',', ' ')
		}
		if m.dialect == "postgres" {
			placeholders = append(placeholders, '$')
			placeholders = append(placeholders, []byte(intToStr(i+1))...)
		} else {
			placeholders = append(placeholders, '?')
		}
		args = append(args, fp)
	}
	q := "SELECT fingerprint, user_label FROM audit_memories " +
		"WHERE user_label IS NOT NULL AND fingerprint IN (" + string(placeholders) + ")"

	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var fp, label string
		if err := rows.Scan(&fp, &label); err != nil {
			continue
		}
		// Most-recent-wins on duplicate fingerprints (the iteration
		// preserves DB row order; subsequent overwrite is fine).
		out[fp] = label
	}
	return out, rows.Err()
}

// intToStr — local stringification to avoid pulling strconv just for one use.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := make([]byte, 0, 8)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// LogQueryStats records the lookup hit rate for observability.
// Safe to call with a nil receiver (no-op).
func (m *MemoryPriorLookup) LogQueryStats(requested int, found int) {
	if m == nil {
		return
	}
	log.Printf("[validate.l4] fingerprints requested=%d labelled=%d", requested, found)
}
