package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

func purge(db *sql.DB, id int, r *http.Request) {
	a, b := fmt.Sprintf("SELECT * FROM t WHERE id = %d", id), fmt.Sprintf("DELETE FROM t WHERE name = '%s'", r.FormValue("n")) // EXPECT: finding
	db.Exec(a)
	db.Exec(b)
}
