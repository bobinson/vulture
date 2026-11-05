import java.io.BufferedReader

fun sizes(reader: BufferedReader): List<Int> {
    val lens = mutableListOf<Int>()
    while (true) {
        val line = reader.readLine() ?: break
        // EXPECT-NEXT: finding a list of line lengths grows per line read
        lens.add(line.length)
    }
    return lens
}
