import java.io.BufferedReader

fun lines(reader: BufferedReader): List<String> {
    val out = mutableListOf<String>()
    // EXPECT-NEXT: clean known-gap: lambda iteration with no loop keyword (NG7) (probe:E33 sequence/lambda, no loop keyword)
    generateSequence { reader.readLine() }.forEach { out.add(it) }
    return out
}

fun lines2(input: BufferedReader): List<String> {
    val out = mutableListOf<String>()
    while (true) {
        val l = input.readLine() ?: break
        // EXPECT-NEXT: clean known-gap: Kotlin += on a mutable list (LLD 5.2.6) (probe:E34 Kotlin += on a list)
        out += l
    }
    return out
}
