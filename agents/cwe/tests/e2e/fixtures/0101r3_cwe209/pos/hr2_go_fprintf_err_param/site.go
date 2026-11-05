package api

import (
	"fmt"
	"net/http"
)

func fail(w http.ResponseWriter, err error) {
	fmt.Fprintf(w, "request failed: %v", err)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err) // EXPECT: finding tp-H-go-fprintf-err-named
		return
	}
}
