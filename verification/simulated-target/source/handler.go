// Sample Go code with planted vulnerabilities for scan agent verification.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// SRC_004: SQL injection via string formatting
func unsafeHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	db, _ := sql.Open("sqlite3", "app.db")
	db.Exec(fmt.Sprintf("DELETE FROM logs WHERE msg = '%s'", query))
	fmt.Fprint(w, "done")
}

// SRC_005: No auth check on admin endpoint
func adminHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "admin panel")
}
