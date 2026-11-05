package push

import "os/exec"

func Push(src, host, dest string) error {
	return exec.Command("rsync", "-az", src, host+":"+dest).Run()
}
