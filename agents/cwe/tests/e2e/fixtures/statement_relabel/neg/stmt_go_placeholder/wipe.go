package m

import (
	"database/sql"
	"net/http"
)

func wipe(tx *sql.Tx, r *http.Request) {
	tx.Exec("DELETE FROM t WHERE id = $1", r.FormValue("id")) // EXPECT: clean
}
