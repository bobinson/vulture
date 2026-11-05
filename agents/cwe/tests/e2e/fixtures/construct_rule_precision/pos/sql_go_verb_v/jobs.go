package repo

import (
	"database/sql"
	"fmt"
)

func remove(db *sql.DB, id string) error {
	_, err := db.Exec(fmt.Sprintf("DELETE FROM jobs WHERE id = %v", id)) // EXPECT: finding
	return err
}
