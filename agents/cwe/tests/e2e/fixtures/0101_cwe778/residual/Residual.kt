// R6 parse fallback to null (fail-closed conversion)
fun port(s: String): Int? {
    try {
        return Integer.parseInt(s)
    } catch (e: NumberFormatException) { // EXPECT: finding known-gap (residual, still reported): R6 Kotlin parse -> null
        return null
    }
}
