// pins: a Go handler passes r.URL.Query().Get("file") straight into ioutil.ReadFile - a request accessor as the path argument in one line; the accessor call is a source read, never also a sink
package main

import (
	"io/ioutil"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data, _ := ioutil.ReadFile(r.URL.Query().Get("file"))
	w.Write(data)
}
