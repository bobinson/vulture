package relay

import (
	"bufio"
	"bytes"
	"net"
)

func Recent(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	recent := []string{}
	for sc.Scan() {
		// EXPECT-NEXT: clean the slice is re-sliced from the front every iteration
		recent = append(recent, sc.Text())
		recent = recent[1:]
	}
}

func Frames(conn net.Conn) {
	buf := new(bytes.Buffer)
	tmp := make([]byte, 512)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			return
		}
		// EXPECT-NEXT: clean the buffer is Reset every iteration
		buf.Write(tmp[:n])
		handle(buf.Bytes())
		buf.Reset()
	}
}

func Slurp(conn net.Conn) []byte {
	var buf bytes.Buffer
	tmp := make([]byte, 512)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			return buf.Bytes()
		}
		// EXPECT-NEXT: finding a zero-value buffer declared with var grows per read
		buf.Write(tmp[:n])
	}
}
