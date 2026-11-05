package api

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func fail(w http.ResponseWriter, msg string) {
	log.Printf("load failed: %s", msg)
	fmt.Fprintln(os.Stderr, msg)
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("internal error"))
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err.Error()) // EXPECT: clean helper-logs-only
		return
	}
}
