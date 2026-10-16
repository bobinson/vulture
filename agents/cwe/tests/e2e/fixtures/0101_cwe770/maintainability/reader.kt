fun slurp(input: java.io.BufferedReader): List<String> {
    val lines = mutableListOf<String>()
    // EXPECT-NEXT: clean known-gap: forEachLine lambda, no loop keyword (NG7) (probe:Kotlin idiomatic stream iteration (no loop keyword))
    input.forEachLine { lines.add(it) }
    return lines
}
fun slurp2(input: java.io.BufferedReader): List<String> {
    val lines = mutableListOf<String>()
    for (line in input.lineSequence()) {
        // EXPECT-NEXT: clean known-gap: lineSequence iteration (NG7) (probe:stream iteration via lineSequence)
        lines.add(line)
    }
    return lines
}
