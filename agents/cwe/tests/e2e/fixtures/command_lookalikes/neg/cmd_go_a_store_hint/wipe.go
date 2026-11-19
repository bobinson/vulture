package m

import "database/sql"

func Wipe(t *sql.Tx, where string) {
	t.Exec("DELETE FROM a WHERE " + where) // EXPECT: clean
}
