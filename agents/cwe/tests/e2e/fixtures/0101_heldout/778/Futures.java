// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// The failure completes a CompletableFuture exceptionally, so whoever joins the future
// receives it. Every identifier is invented.
// HELD-OUT-TOKENS: CompletableFuture, completeExceptionally, failedFuture

class GalleryLoader {
    void loadAlbum(String albumId, CompletableFuture<Album> future) {
        try {
            future.complete(albumRepository.read(albumId));
        } catch (IOException e) { // EXPECT: finding held-out-miss (concept: clean)
            future.completeExceptionally(e);
        }
    }

    void checkDetachedSignature(byte[] payload, CompletableFuture<Boolean> future) {
        try {
            future.complete(signatureVerifier.verify(payload));
        } catch (GeneralSecurityException e) { // EXPECT: finding
            future.completeExceptionally(e);
        }
    }

    CompletableFuture<Forecast> forecastFor(String city) {
        try {
            return CompletableFuture.completedFuture(weatherClient.fetch(city));
        } catch (TimeoutException e) { // EXPECT: clean
            return CompletableFuture.failedFuture(e);
        }
    }
}
