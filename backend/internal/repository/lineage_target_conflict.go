package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/vulture/backend/internal/model"
)

// Feature 0091 — THE SECOND UNIQUE KEY ON finding_lineage.
//
// THE DEFECT THIS EXISTS FOR. Migration 027 step 6 adds a SECOND unique index:
//
//	uq_lineage_target (target_key, agent_type,
//	                   COALESCE(NULLIF(fingerprint_v2,''), fingerprint))
//	WHERE merged_into IS NULL
//
// while the upsert's conflict target still names only the pre-existing
// uq_lineage (fingerprint, source_path, agent_type). A write that satisfies
// the first key and collides on the second is not caught by the upsert at all:
// Postgres raises 23505, SQLite raises SQLITE_CONSTRAINT_UNIQUE,
// createNewLineage returns the error, and upsertFindings does nothing but
// log.Printf it. The finding then has NO lineage row — no VLT ref, no
// first-seen date, no timeline, and no presence in the target report — for
// this scan and every later one while the trigger holds. Silently, in a
// detached goroutine, after the audit has already been reported complete.
//
// WHY IT BECAME REACHABLE. Before 0091 the index key COALESCEd down to the v1
// fingerprint, which hashes the RAW file path, so two mounts of one tree
// produced two different keys and never collided. `fingerprint_v2` is
// deliberately mount-INVARIANT and is now stamped at shipped defaults, which
// is exactly what the matching rule needs and exactly what makes the index
// bite. Three paths reach createNewLineage with a v2 that already exists under
// the target:
//
//   - VULTURE_LINEAGE_KEY=path, the documented rollback: its lookup is scoped
//     to the CURRENT source_path, so the other mount's row is invisible to it
//     while createNewLineage still writes target_key unconditionally;
//   - a batch lookup that failed and degraded to "nothing matched"
//     (logLookup), which sends every finding of that batch down the create
//     branch;
//   - two findings in ONE batch that share a check_id, canonical path,
//     category and agent but differ in title: same v2, different v1.
//
// THE RECOVERY. The index has just told us the row exists; the answer is to go
// and get it and take the update branch, which is what the lookup would have
// done had it seen the row. Recovery rather than a pre-emptive second SELECT
// on every write because the collision is the rare path and the ordinary one
// must not pay for it.

// lineageTargetIdentity is the value uq_lineage_target keys a row on. It
// mirrors the index expression COALESCE(NULLIF(fingerprint_v2, empty),
// fingerprint) exactly; a divergence here would look up a different row than
// the one the index refused, which is worse than not recovering at all.
func lineageTargetIdentity(l *model.FindingLineage) string {
	if v := strings.TrimSpace(l.FingerprintV2); v != "" {
		return v
	}
	return l.Fingerprint
}

// isTargetIdentityConflict reports whether err is the unique violation on
// uq_lineage_target specifically.
//
// Scoped to that one constraint on purpose. A violation of uq_lineage
// (fingerprint, source_path, agent_type) is already handled by the upsert's
// own ON CONFLICT, so seeing one here would mean something else is wrong and
// swallowing it would hide it. SQLite reports no constraint name in a typed
// field, so its arm matches the index name in the driver's message — the same
// string sqlite3 always emits for a named index ("UNIQUE constraint failed:
// index 'uq_lineage_target'").
func isTargetIdentityConflict(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505" && pqErr.Constraint == "uq_lineage_target"
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, "uq_lineage_target")
}

// targetConflictSQL is the lookup both dialects run after the index refuses a
// write: the live row under this target that already holds this identity.
// `merged_into IS NULL` mirrors the index's own partial predicate — a merged
// loser is outside the index and cannot be what refused us.
const targetConflictSQL = `
	SELECT id, COALESCE(ref_number, 0) FROM finding_lineage
	 WHERE target_key = %s AND agent_type = %s
	   AND COALESCE(NULLIF(fingerprint_v2,''), fingerprint) = %s
	   AND merged_into IS NULL`

// findTargetConflictRow returns the id and ref of the colliding row, or
// ("", 0) when it cannot be found.
//
// Not finding it is possible and is not an error worth failing on: the row can
// have been merged or deleted between the failed write and this read. The
// caller then reports the original conflict, which is the honest outcome.
func findTargetConflictRow(db *sql.DB, l *model.FindingLineage, pg bool) (string, int, error) {
	d := &sqlDialect{pg: pg}
	q := fmt.Sprintf(targetConflictSQL,
		d.ph(l.TargetKey), d.ph(l.AgentType), d.ph(lineageTargetIdentity(l)))
	var id string
	var ref int
	err := db.QueryRow(q, d.args...).Scan(&id, &ref)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("find target-identity conflict row: %w", err)
	}
	return id, ref, nil
}
