package api

import "net/http"

func fail(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusInternalServerError)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, "could not load the item") // EXPECT: clean literal-message
		return
	}
}
