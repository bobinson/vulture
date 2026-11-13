package svc

import "net/http"

var client = &http.Client{}

func Forward(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequest(http.MethodGet, r.FormValue("u"), nil)
	client.Do(req) // EXPECT: finding check=cwe.injection.ssrf
	http.DefaultClient.Do(req) // EXPECT: finding check=cwe.injection.ssrf
}
