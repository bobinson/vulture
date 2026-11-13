package svc

import (
	"io"
	"net/http"
)

func get(target string) (*http.Response, error) {
	return http.Get(target)
}

func post(target string, body io.Reader) (*http.Response, error) {
	return http.Post(target, "application/json", body)
}

func do(target string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	return http.DefaultClient.Do(req)
}
