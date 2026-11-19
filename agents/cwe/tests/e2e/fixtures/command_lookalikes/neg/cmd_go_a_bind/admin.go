package m

import "database/sql"

func Mk(dsn string, name string) {
	admin, _ := sql.Open("pgx", dsn)
	admin.Exec("CREATE DATABASE " + name) // EXPECT: clean
}
