package relay

import (
	"net"
	"sync"
	"sync/atomic"
)

func Serve(ln net.Listener) {
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		// EXPECT-NEXT: clean WaitGroup counter, not allocation
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handle(c)
		}(conn)
	}
	wg.Wait()
}

func ServeLiteral(ln net.Listener) {
	wg := sync.WaitGroup{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// EXPECT-NEXT: clean WaitGroup declared by literal
		wg.Add(1)
		go handle(conn)
	}
}

func ServeCounted(ln net.Listener) {
	var received atomic.Int64
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// EXPECT-NEXT: clean atomic declared with var, Add of a literal
		received.Add(1)
		go handle(conn)
	}
}

func Sum(ch chan int) {
	var mu sync.Mutex
	var acc atomic.Int64
	for v := range ch {
		// EXPECT-NEXT: clean numeric conversion argument
		acc.Add(int64(v))
		mu.Lock()
		mu.Unlock()
	}
}

func Keep(ln net.Listener) []net.Conn {
	var conns []net.Conn
	for {
		conn, err := ln.Accept()
		if err != nil {
			return conns
		}
		// EXPECT-NEXT: finding every accepted connection retained
		conns = append(conns, conn)
	}
}

type set map[string]struct{}

func (s set) Add(k string) { s[k] = struct{}{} }

func Remember(conn net.Conn, seen set) {
	buf := make([]byte, 64)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// EXPECT-NEXT: finding a peer-chosen key added to a set
		seen.Add(string(buf[:n]))
	}
}
