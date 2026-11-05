package scan

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

func SplitLines(s string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		// EXPECT-NEXT: clean F13 scanner over an in-memory string
		lines = append(lines, sc.Text())
	}
	return lines
}

func Limited(conn net.Conn) []string {
	var lines []string
	sc := bufio.NewScanner(io.LimitReader(conn, 1<<20))
	for sc.Scan() {
		// EXPECT-NEXT: clean F14 source wrapped in LimitReader
		lines = append(lines, sc.Text())
	}
	return lines
}

func Body(w http.ResponseWriter, r *http.Request) []string {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var out []string
	sc := bufio.NewScanner(r.Body)
	for sc.Scan() {
		// EXPECT-NEXT: clean F15 MaxBytesReader caps the body
		out = append(out, sc.Text())
	}
	return out
}

var octetCount atomic.Int64

func Count(conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// EXPECT-NEXT: clean F16 atomic counter Add, not allocation
		octetCount.Add(int64(n))
	}
}

func Names(xs []string) []string {
	// EXPECT-NEXT: finding the protected Go make arm (NG2) reports independently of the loop below
	out := make([]string, 0)
	for _, x := range xs {
		// EXPECT-NEXT: clean F17 range over in-memory slice
		out = append(out, x)
	}
	return out
}
