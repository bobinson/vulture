package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vulture/backend/internal/localdev"
	"github.com/vulture/backend/internal/server"
)

// runLogs implements `vulture logs [-f] [agent]`. Output passes
// through the redactor (S16) so secrets that may have ended up in
// the on-disk log file are still masked at display time.
func runLogs() {
	args := os.Args[2:]
	follow := false
	target := "backend"
	for _, a := range args {
		switch a {
		case "-f", "--follow":
			follow = true
		default:
			target = a
		}
	}
	mode := localdev.DetectMode()
	logsDir := filepath.Join(localdev.DataDir(mode, "."), "logs")
	path := filepath.Join(logsDir, target+".log")
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "no log file at %s\n", path)
		os.Exit(1)
	}
	if follow {
		tailFollow(path)
		return
	}
	tailOnce(path)
}

func tailOnce(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fmt.Println(server.RedactLine(sc.Text()))
	}
}

func tailFollow(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	_, _ = f.Seek(0, io.SeekEnd)
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			fmt.Print(server.RedactLine(line))
		}
		if err == io.EOF {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if err != nil {
			return
		}
	}
}
