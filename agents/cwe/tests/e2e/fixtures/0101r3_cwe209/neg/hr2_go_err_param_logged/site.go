package api

import (
	"fmt"
	"log"
	"net/http"
)

func fail(w http.ResponseWriter, err error) {
	log.Printf("request failed: %v", err)
	fmt.Fprint(w, "internal error")
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err) // EXPECT: clean helper-logs-err-writes-literal
		return
	}
}
