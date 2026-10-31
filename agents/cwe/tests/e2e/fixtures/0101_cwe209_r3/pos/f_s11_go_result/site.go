package ledger

import "net/http"

type Outcome struct{ Err string }

func load(id string) Outcome {
	if _, err := store.Read(id); err != nil {
		return Outcome{Err: err.Error()}
	}
	return Outcome{}
}

func Show(w http.ResponseWriter, r *http.Request) {
	outcome := load(r.URL.Query().Get("id"))
	w.Write([]byte(outcome.Err)) // EXPECT: finding tp
}
