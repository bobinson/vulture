func slurp() -> [String] {
    var lines: [String] = []
    while let line = readLine() {
        // EXPECT-NEXT: finding swift readLine
        lines.append(line)
    }
    return lines
}
