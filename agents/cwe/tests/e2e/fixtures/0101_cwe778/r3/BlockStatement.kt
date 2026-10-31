// Feature 0101, CWE-778 Concept A, Kotlin (RED round 2, R2-2). `withContext(...) {`
// and `synchronized(...) {` are block statements inside the routine: the routine
// name above them is part of the window. Every identifier is invented.
class RecordStore {
    var lastError: Throwable? = null

    suspend fun revokeAllGrants(userId: String) {
        withContext(Dispatchers.IO) {
            try {
                store.deleteAll(userId)
            } catch (e: Exception) { // EXPECT: finding
                this.lastError = e
            }
        }
    }

    suspend fun refreshCounters(userId: String) {
        withContext(Dispatchers.IO) {
            try {
                store.deleteAll(userId)
            } catch (e: Exception) { // EXPECT: clean
                this.lastError = e
            }
        }
    }

    fun revokeAllTokens(userId: String) {
        synchronized(lock) {
            try {
                store.deleteAll(userId)
            } catch (e: Exception) { // EXPECT: finding
                this.lastError = e
            }
        }
    }

    fun compactPages(userId: String) {
        synchronized(lock) {
            try {
                store.deleteAll(userId)
            } catch (e: Exception) { // EXPECT: clean
                this.lastError = e
            }
        }
    }
}
