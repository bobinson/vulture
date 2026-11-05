package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

func find(db *sql.DB, args []any) error {
	q := fmt.Sprintf("SELECT * FROM t WHERE name = '%d'", args...) // EXPECT: finding
	_, err := db.Query(q)
	return err
}
