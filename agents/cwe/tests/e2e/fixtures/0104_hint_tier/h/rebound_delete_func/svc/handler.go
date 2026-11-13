package svc

import "net/http"

func delete(target string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodDelete, target, nil)
	return http.DefaultClient.Do(req) // EXPECT: finding check=cwe.injection.ssrf
}

func Purge(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("t")
	delete(target)
}
