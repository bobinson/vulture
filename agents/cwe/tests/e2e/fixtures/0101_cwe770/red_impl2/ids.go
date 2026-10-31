package relay

import (
	"bufio"
	"net"
	"strconv"
	"sync/atomic"
)

func Ids(conn net.Conn) []int64 {
	set := NewSet()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		v, _ := strconv.ParseInt(sc.Text(), 10, 64)
		// EXPECT-NEXT: finding a set constructed in the routine grows per scanned line
		set.Add(int64(v))
	}
	return set.Items()
}

func Octets(conn net.Conn) int64 {
	var octets atomic.Int64
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return octets.Load()
		}
		// EXPECT-NEXT: clean an atomic declared in the routine is arithmetic
		octets.Add(int64(n))
	}
}
