// pins: Go's predeclared append and copy are slice builtins, never path sinks - both applied to request values (negative)
package main

import "net/http"

func collectTags(w http.ResponseWriter, r *http.Request) {
	tags := []string{}
	for _, tag := range r.URL.Query()["tag"] {
		tags = append(tags, tag)
	}
	label := make([]byte, 16)
	copy(label, r.URL.Query().Get("label"))
	w.Write(label)
}
