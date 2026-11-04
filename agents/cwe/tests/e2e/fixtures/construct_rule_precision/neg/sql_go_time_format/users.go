package repo

import (
	"database/sql"
	"time"
)

func touch(db *sql.DB, id string) error {
	_, err := db.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id) // EXPECT: clean
	return err
}
