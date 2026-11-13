package svc

import "net/http"

type getter func(string) (*http.Response, error)

func Relay(w http.ResponseWriter, r *http.Request, get getter) {
	get(r.FormValue("u")) // EXPECT: finding check=cwe.injection.ssrf
}
