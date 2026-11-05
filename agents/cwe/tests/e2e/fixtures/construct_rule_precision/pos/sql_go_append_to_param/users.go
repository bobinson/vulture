package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, sets string, id int) error {
	sets += ", updated_at = now()"
	q := fmt.Sprintf("UPDATE users SET %s WHERE id = $1", sets) // EXPECT: finding
	_, err := db.Exec(q, id)
	return err
}
