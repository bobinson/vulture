package svc

import "net/http"

func Delete(target string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, target, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
