package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

func update(db *sql.DB, r *http.Request) error {
	sets, err := clause(r)
	if err != nil {
		return err
	}
	q := fmt.Sprintf("UPDATE users SET %s WHERE id = $1", sets) // EXPECT: finding
	_, err = db.Exec(q, r.FormValue("id"))
	return err
}
