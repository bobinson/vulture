class Ingest {
    fun slurp(input: BufferedReader): List<String> {
        val lines = mutableListOf<String>()
        while (true) {
            val l = input.readLine() ?: break
            // EXPECT-NEXT: finding kotlin readLine
            lines.add(l)
        }
        return lines
    }
}
