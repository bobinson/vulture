package api

import (
	"net/http"
)

func fail(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err) // EXPECT: clean the-helper-line-is-the-report
		return
	}
}
