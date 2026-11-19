package m

import (
	"database/sql"
	"net/http"
)

func run(t *sql.Tx, r *http.Request) {
	t.Exec(r.FormValue("q")) // EXPECT: finding
}
