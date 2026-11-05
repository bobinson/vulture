def slurp(sock)
  lines = []
  while line = sock.gets
    # EXPECT-NEXT: finding ruby << accumulation
    lines << line
  end
  lines
end

def slurp2(sock)
  lines = []
  while line = sock.gets
    # EXPECT-NEXT: finding ruby push
    lines.push(line)
  end
  lines
end
