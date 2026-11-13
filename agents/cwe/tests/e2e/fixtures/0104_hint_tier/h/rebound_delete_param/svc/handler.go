package svc

import "net/http"

func run(delete func(string) (*http.Response, error), target string) {
	delete(target) // EXPECT: finding check=cwe.injection.ssrf
}

func Purge(w http.ResponseWriter, r *http.Request) {
	run(http.Get, r.FormValue("t"))
}
