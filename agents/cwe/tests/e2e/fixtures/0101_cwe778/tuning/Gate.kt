// Feature 0101 tuning fixture (round-0 held-out, now tuning): invented identifiers.
class Gate(private val keySpec: Key) {
    private var lastError: Throwable? = null
    fun payloadIsAuthentic(body: ByteArray, sig: ByteArray): Boolean {
        return try {
            val mac = Mac.getInstance(ALGO)
            mac.init(keySpec)
            MessageDigest.isEqual(mac.doFinal(body), sig)
        } catch (e: GeneralSecurityException) { // EXPECT: finding
            lastError = e
            false
        }
    }
}
