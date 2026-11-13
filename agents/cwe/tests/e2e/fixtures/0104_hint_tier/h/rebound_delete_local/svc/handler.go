package svc

import "net/http"

func Purge(w http.ResponseWriter, r *http.Request) {
	delete := func(target string) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodDelete, target, nil)
		return http.DefaultClient.Do(req) // EXPECT: finding check=cwe.injection.ssrf
	}
	delete(r.FormValue("t"))
}
