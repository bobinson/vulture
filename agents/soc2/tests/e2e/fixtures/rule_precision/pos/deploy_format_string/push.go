package push

import (
	"fmt"
	"os/exec"
)

func Push(host, dir string) error {
	return exec.Command("rsync", "-az", "dist/", fmt.Sprintf("%s:%s", host, dir)).Run()
}
