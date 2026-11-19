package m

import "net/http"

func wipe(db X, r *http.Request) {
	db.Exec("DELETE FROM t WHERE id = " + r.FormValue("id")) // EXPECT: finding
}
