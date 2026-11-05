package repo

import (
	"database/sql"
	"fmt"
)

func update(db *sql.DB, userCol string) error {
	sets := userCol
	reset := func() { sets := "a = 1"; _ = sets }
	reset()
	q := fmt.Sprintf("UPDATE t SET %s", sets) // EXPECT: finding
	_, err := db.Exec(q)
	return err
}
