def drain(sock)
  buf = []
  while line = sock.gets
    # EXPECT-NEXT: finding E29 Ruby << and paren-less gets
    buf << line
  end
  buf
end

def drain2(sock)
  lines = []
  sock.each_line do |l|
    # EXPECT-NEXT: clean known-gap: block iteration with no loop keyword (NG7) (probe:E30 block iteration, no loop keyword)
    lines.push(l)
  end
  lines
end

def drain3(sock)
  out = []
  loop do
    chunk = sock.readpartial(4096)
    # EXPECT-NEXT: finding E31 readpartial not a pull verb
    out.push(chunk)
  end
rescue EOFError
  out
end
