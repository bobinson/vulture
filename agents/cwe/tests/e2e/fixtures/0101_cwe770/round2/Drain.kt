fun drain(input: java.io.InputStream): MutableList<ByteArray> {
    val sink = mutableListOf<ByteArray>()
    val buf = ByteArray(8192)
    while (true) {
        val n = input.read(buf)
        if (n <= 0) break
        // EXPECT-NEXT: finding Kotlin read loop
        sink.add(buf.copyOf(n))
    }
    return sink
}
