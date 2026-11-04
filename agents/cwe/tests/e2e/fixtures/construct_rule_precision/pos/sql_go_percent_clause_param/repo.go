package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, name string) error {
	sets := "a = 1"
	q := fmt.Sprintf("UPDATE t SET %s WHERE n = '%s'", sets, name) // EXPECT: finding
	_, err := db.Exec(q)
	return err
}
