package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, col string, id int) error {
	sets := col + " = $1"
	q := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", sets, 2) // EXPECT: finding
	_, err := db.Exec(q, "x", id)
	return err
}
