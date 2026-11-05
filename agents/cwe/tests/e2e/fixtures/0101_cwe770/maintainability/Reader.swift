func slurp() -> [String] {
    var lines: [String] = []
    while let line = readLine() {
        // EXPECT-NEXT: finding Swift readLine
        lines.append(line)
    }
    return lines
}
