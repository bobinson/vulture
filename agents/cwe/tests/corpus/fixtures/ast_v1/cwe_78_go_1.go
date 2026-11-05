// Pins: exec.Command("sh", "-c", form.Cmd) where form is filled by json.NewDecoder(r.Body).Decode(&form) (output parameter + shell flag).
package app

func taskHook(r *http.Request) error {
	var form struct{ Cmd string }
	json.NewDecoder(r.Body).Decode(&form)
	return exec.Command("sh", "-c", form.Cmd).Run()
}
