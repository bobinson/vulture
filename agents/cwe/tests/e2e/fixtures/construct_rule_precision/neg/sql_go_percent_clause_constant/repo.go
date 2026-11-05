package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, id int) error {
	sets := "a = 1"
	kind := "daily"
	q := fmt.Sprintf("UPDATE t SET %s WHERE kind = '%s' AND id = %d", sets, kind, id) // EXPECT: clean
	_, err := db.Exec(q)
	return err
}
