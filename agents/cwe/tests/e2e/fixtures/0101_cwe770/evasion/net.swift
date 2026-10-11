func drain(_ stream: InputStream) -> [UInt8] {
    var out: [UInt8] = []
    var buf = [UInt8](repeating: 0, count: 4096)
    repeat {
        let n = stream.read(&buf, maxLength: buf.count)
        if n <= 0 { break }
        // EXPECT-NEXT: finding E36 repeat/while loop keyword
        out.append(contentsOf: buf[0..<n])
    } while true
    return out
}
