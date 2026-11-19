package m

import (
	"database/sql"
	"net/http"
)

func mk(t *sql.Tx, r *http.Request) {
	t.Exec("CREATE TABLE " + r.FormValue("n") + " (id int)") // EXPECT: finding
}
