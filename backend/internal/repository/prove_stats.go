package repository

import (
	"database/sql"
	"fmt"

	"github.com/vulture/backend/internal/model"
)

// scanProveStats populates the prove-related fields of DashboardStats
// from the prove_results table. Shared by both SQLite and Postgres repos.
func scanProveStats(db *sql.DB, stats *model.DashboardStats) error {
	if err := db.QueryRow(`SELECT COUNT(*) FROM prove_results WHERE status = 'verified'`).Scan(&stats.ProveVerified); err != nil {
		return fmt.Errorf("count prove verified: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM prove_results`).Scan(&stats.ProveTotal); err != nil {
		return fmt.Errorf("count prove total: %w", err)
	}
	return nil
}
