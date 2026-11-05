// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// A suspended coroutine resumes its caller with the failure, or a function returns it
// inside a Result: the caller receives it. Every identifier is invented.
// HELD-OUT-TOKENS: suspendCancellableCoroutine, resumeWithException, Result, CancellationException

suspend fun readTileBytes(path: String): ByteArray = suspendCancellableCoroutine { cont ->
    tileExecutor.submit {
        try {
            cont.resume(tileStore.readAllBytes(path))
        } catch (e: IOException) { // EXPECT: clean
            cont.resumeWithException(e)
        }
    }
}

suspend fun verifyAssertion(assertion: String): Principal = suspendCancellableCoroutine { cont ->
    signerExecutor.submit {
        try {
            cont.resume(assertionVerifier.verifySignature(assertion))
        } catch (e: GeneralSecurityException) { // EXPECT: finding
            cont.resumeWithException(e)
        }
    }
}

fun parseColour(hex: String): Result<Colour> {
    try {
        return Result.success(Colour.fromHex(hex))
    } catch (e: NumberFormatException) { // EXPECT: clean
        return Result.failure(e)
    }
}

suspend fun refreshBanner() {
    try {
        bannerCache.reload()
    } catch (e: CancellationException) { // EXPECT: finding
    }
}
