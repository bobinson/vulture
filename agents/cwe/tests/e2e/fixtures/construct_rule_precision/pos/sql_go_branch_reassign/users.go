package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, override string, id int) error {
	sets := "name = $1"
	if override != "" {
		sets = override
	}
	q := fmt.Sprintf("UPDATE users SET %s WHERE id = $2", sets) // EXPECT: finding
	_, err := db.Exec(q, "x", id)
	return err
}
