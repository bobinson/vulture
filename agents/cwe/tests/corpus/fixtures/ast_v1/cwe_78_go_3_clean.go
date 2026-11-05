// pins: a data store is no process - db.Exec(...) on a database handle runs SQL (CWE-89's concern), not an OS command, though the statement is built from a query parameter (negative)
package drafts

import (
	"database/sql"
	"net/http"
)

func purge(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	db.Exec("DELETE FROM drafts WHERE owner = '" + owner + "'")
	w.WriteHeader(http.StatusNoContent)
}
