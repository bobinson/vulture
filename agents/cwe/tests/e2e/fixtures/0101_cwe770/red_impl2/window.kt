import java.io.BufferedReader

fun pump(reader: BufferedReader) {
    val recent = ArrayDeque<String>()
    while (true) {
        val line = reader.readLine() ?: break
        // EXPECT-NEXT: clean removeFirst keeps the deque at one entry
        recent.addLast(line)
        recent.removeFirst()
    }
}
