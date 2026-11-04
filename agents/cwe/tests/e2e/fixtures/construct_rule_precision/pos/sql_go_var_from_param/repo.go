package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, userCol string) error {
	var sets string = userCol
	q := fmt.Sprintf("UPDATE t SET %s", sets) // EXPECT: finding
	_, err := db.Exec(q)
	return err
}
