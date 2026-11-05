// Pins: an allowlist guard `if !slices.Contains(allowedCmds, form.Cmd) { return }` before exec.Command("sh", "-c", form.Cmd).
package app

func taskHook(r *http.Request) error {
	var form struct{ Cmd string }
	json.NewDecoder(r.Body).Decode(&form)
	if !slices.Contains(allowedCmds, form.Cmd) {
		return errDenied
	}
	return exec.Command("sh", "-c", form.Cmd).Run()
}
