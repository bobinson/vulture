package handler

import "os/exec"

func Extract(r *Request) error {
	cmd := exec.Command("tar", "-C"+r.FormValue("dir"), "-xf", "archive.tar")
	return cmd.Run()
}
