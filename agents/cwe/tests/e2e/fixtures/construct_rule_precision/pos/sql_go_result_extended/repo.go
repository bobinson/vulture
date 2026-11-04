package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

func find(db *sql.DB, name string) error {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %d", 1) // EXPECT: finding
	q += " AND name = '" + name + "'"
	_, err := db.Query(q)
	return err
}
