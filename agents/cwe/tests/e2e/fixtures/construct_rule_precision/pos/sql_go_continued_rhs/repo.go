package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, userCol string) error {
	sets := "name = " +
		userCol
	q := fmt.Sprintf("UPDATE t SET %s", sets) // EXPECT: finding
	_, err := db.Exec(q)
	return err
}
