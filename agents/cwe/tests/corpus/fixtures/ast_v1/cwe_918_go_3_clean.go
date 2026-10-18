// Pins: os.Open(name) where name := r.URL.Query().Get("f"); open is a request-sink word only in browser-capable profiles, so in Go it is a path sink and never SSRF (a CWE-22 positive, scored here only as a CWE-918 clean).
package app

func openDoc(r *http.Request) (*os.File, error) {
	name := r.URL.Query().Get("f")
	return os.Open(name)
}
