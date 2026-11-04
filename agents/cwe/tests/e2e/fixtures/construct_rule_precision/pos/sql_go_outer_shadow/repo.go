package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

var where string

func find(db *sql.DB) error {
	where := " WHERE 1=1" + where
	q := fmt.Sprintf("SELECT * FROM t%s", where) // EXPECT: finding
	_, err := db.Query(q)
	return err
}
