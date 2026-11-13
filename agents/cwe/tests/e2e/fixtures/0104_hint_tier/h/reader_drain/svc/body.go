package svc

import (
	"io"
	"io/ioutil"
	"net/http"
)

func Echo(w http.ResponseWriter, r *http.Request) {
	b1, _ := io.ReadAll(r.Body) // EXPECT: clean check=cwe.input_validation.path_traversal
	b2, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // EXPECT: clean check=cwe.input_validation.path_traversal
	b3, _ := ioutil.ReadAll(r.Body) // EXPECT: clean check=cwe.input_validation.path_traversal
	resp, err := http.Get("https://svc.example.invalid/x")
	if err == nil {
		b4, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // EXPECT: clean check=cwe.input_validation.path_traversal
		w.Write(b4)
	}
	w.Write(append(append(b1, b2...), b3...))
}
