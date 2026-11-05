package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, cols []string) error {
	sets := "id = id"
	for i := 0; i < len(cols); sets += ", " + cols[i] {
		i++
	}
	q := fmt.Sprintf("UPDATE t SET %s", sets) // EXPECT: finding
	_, err := db.Exec(q)
	return err
}
