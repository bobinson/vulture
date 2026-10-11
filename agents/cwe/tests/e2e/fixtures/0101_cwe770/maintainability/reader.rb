def slurp(sock)
  lines = []
  while (line = sock.gets)
    # EXPECT-NEXT: finding Ruby append operator
    lines << line
  end
  lines
end

def slurp2(sock)
  lines = []
  while (line = sock.gets)
    # EXPECT-NEXT: finding Ruby push
    lines.push(line)
  end
  lines
end
