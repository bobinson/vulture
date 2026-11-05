package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, cols []string) error {
	prev := "a = 1"
	for _, c := range cols {
		if _, err := db.Exec(fmt.Sprintf("UPDATE t SET %s", prev)); err != nil { // EXPECT: finding
			return err
		}
		prev = c + " = 1"
	}
	return nil
}
