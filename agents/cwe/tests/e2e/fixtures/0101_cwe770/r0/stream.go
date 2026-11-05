package main

func readAll(conn Conn) []byte {
	buf := make([]byte, 4096)
	var data []byte
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		// EXPECT-NEXT: finding P6
		data = append(data, buf[:n]...)
	}
	return data
}

func lines(scanner *Scanner) []string {
	var out []string
	for scanner.Scan() {
		// EXPECT-NEXT: finding P7
		out = append(out, scanner.Text())
	}
	return out
}

func batch(ch chan Msg) []Msg {
	var b []Msg
	for {
		msg := <-ch
		// EXPECT-NEXT: finding P8
		b = append(b, msg)
	}
}

func fromRows(rows Rows) []Item {
	var out []Item
	for rows.Next() {
		var v Item
		rows.Scan(&v)
		// EXPECT-NEXT: clean N8
		out = append(out, v)
	}
	return out
}

func counted(n int) []int {
	var out []int
	for i := 0; i < n; i++ {
		// EXPECT-NEXT: clean N9
		out = append(out, i)
	}
	return out
}

func ranged(xs []int) []int {
	var out []int
	for _, x := range xs {
		// EXPECT-NEXT: clean N10
		out = append(out, x)
	}
	return out
}
