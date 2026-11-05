package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

func find(db *sql.DB, id int, name string) error {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id) + " AND name = '" + name + "'" // EXPECT: finding
	_, err := db.Query(q)
	return err
}
