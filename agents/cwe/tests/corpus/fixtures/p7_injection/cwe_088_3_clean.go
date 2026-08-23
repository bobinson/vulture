package handler

import "os/exec"

func Extract(dir string) error {
	cmd := exec.Command("tar", "-C", dir, "-xf", "archive.tar")
	return cmd.Run()
}
