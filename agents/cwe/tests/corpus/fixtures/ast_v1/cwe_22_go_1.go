// Pins: os.ReadFile(filepath.Join(rootDir, r.URL.Query().Get("f"))) in a func(w, r *http.Request) handler; Join is a builder, not a sanitizer.
package app

const rootDir = "/srv/docs"

func showDoc(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(filepath.Join(rootDir, r.URL.Query().Get("f")))
	fmt.Fprintf(w, "%s", data)
}
