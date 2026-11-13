package svc

import "net/http"

func Purge(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("t")
	resp, err := Delete(target) // EXPECT: finding check=cwe.injection.ssrf
	if err == nil {
		resp.Body.Close()
	}
}
