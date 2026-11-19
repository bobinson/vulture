package m

import (
	"database/sql"
	"fmt"
	"net/http"
)

func wipe(t *sql.Tx, r *http.Request) {
	t.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", r.FormValue("id"))) // EXPECT: finding
}
