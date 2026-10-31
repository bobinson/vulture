// Feature 0101 tuning fixture (round-0 held-out, now tuning): invented identifiers.

import java.io.IOException

class Loader(private val store: Store) {
    private val failures = mutableListOf<Throwable>()
    private var failed = false

    fun readManifest(path: String): Result<String> {
        try {
            return Result.success(store.read(path))
        } catch (e: IOException) { // EXPECT: clean
            return Result.failure(e)
        }
    }

    fun warmCache(keys: List<String>) {
        for (k in keys) {
            try {
                store.read(k)
            } catch (e: IOException) { // EXPECT: clean
                failures.add(e)
            }
        }
    }

    fun refresh() {
        try {
            store.reload()
        } catch (ex: IOException) { // EXPECT: clean
            onReloadFailure(ex)
        }
    }

    fun verifyTokenSignature(token: String): Result<Boolean> {
        try {
            return Result.success(store.verifySignature(token))
        } catch (e: IOException) { // EXPECT: finding
            return Result.failure(e)
        }
    }

    fun readOptional(path: String): String? {
        try {
            return store.read(path)
        } catch (e: IOException) { // EXPECT: finding
            return null
        }
    }

    fun touch(path: String) {
        try {
            store.touch(path)
        } catch (e: IOException) { // EXPECT: finding
        }
    }

    fun flagOnly(path: String) {
        try {
            store.touch(path)
        } catch (e: IOException) { // EXPECT: finding
            failed = true
        }
    }

    fun tidy(path: String) {
        try {
            store.touch(path)
        } catch (e: IOException) { // EXPECT: finding
            cleanup(e)
        }
    }

    fun typeOnly(path: String): String {
        try {
            return store.read(path)
        } catch (e: IOException) { // EXPECT: finding
            return "failed: " + e.javaClass.simpleName
        }
    }

    private fun onReloadFailure(t: Throwable) { failures.add(t) }
    private fun cleanup(t: Throwable) {}
}
