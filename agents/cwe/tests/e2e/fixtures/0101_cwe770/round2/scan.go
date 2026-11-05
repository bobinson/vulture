package p

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

func Plain(conn net.Conn) []string {
	var lines []string
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		// EXPECT-NEXT: finding uncapped scanner over a connection
		lines = append(lines, sc.Text())
	}
	return lines
}

func Wrapped(conn net.Conn) []string {
	var lines []string
	sc := bufio.NewScanner(io.LimitReader(conn, 1<<20))
	for sc.Scan() {
		// EXPECT-NEXT: clean cap wrapper on the receiver binding
		lines = append(lines, sc.Text())
	}
	return lines
}

func Hop(w http.ResponseWriter, r *http.Request) []string {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var out []string
	sc := bufio.NewScanner(r.Body)
	for sc.Scan() {
		// EXPECT-NEXT: clean cap wrapper one hop away
		out = append(out, sc.Text())
	}
	return out
}
