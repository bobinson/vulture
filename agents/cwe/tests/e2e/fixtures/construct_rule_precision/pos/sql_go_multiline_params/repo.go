package repo

import (
	"database/sql"
	"fmt"
)

func update(
	db *sql.DB,
	sets string,
) error {
	if len(sets) > 64 {
		sets := "a = 1"
		_ = sets
	}
	q := fmt.Sprintf("UPDATE t SET %s", sets) // EXPECT: finding
	_, err := db.Exec(q)
	return err
}
