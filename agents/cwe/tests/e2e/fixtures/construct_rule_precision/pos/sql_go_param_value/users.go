package repo

import (
	"database/sql"
	"fmt"
)

func find(db *sql.DB, name string) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name) // EXPECT: finding
	return db.Query(q)
}
