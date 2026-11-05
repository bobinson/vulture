package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

func find(db *sql.DB, r *http.Request) error {
	col := "name"
	decode(r, &(col))
	q := fmt.Sprintf("SELECT %s FROM t", col) // EXPECT: finding
	_, err := db.Query(q)
	return err
}
