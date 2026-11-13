package svc

import (
	"encoding/json"
	"net/http"
)

func Strip(w http.ResponseWriter, r *http.Request) {
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	delete(m, "token") // EXPECT: clean check=cwe.injection.ssrf
	q := r.URL.Query()
	delete(q, "sig") // EXPECT: clean check=cwe.injection.ssrf
	resp, err := http.Get("https://svc.example.invalid/x")
	if err == nil {
		var wm map[string]any
		json.NewDecoder(resp.Body).Decode(&wm)
		delete(wm, "name") // EXPECT: clean check=cwe.injection.ssrf
	}
}
