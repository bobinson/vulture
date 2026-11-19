package m

import "database/sql"

func Mk(h *sql.DB, name string) {
	h.Exec("CREATE TABLE " + name + " (id int)") // EXPECT: clean
}
