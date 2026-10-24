// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// A checked continuation resumes its awaiting caller by throwing the failure.
// Every identifier is invented.
// HELD-OUT-TOKENS: withCheckedThrowingContinuation, resume, throwing, returning

func loadArtwork(named name: String) async throws -> Artwork {
    try await withCheckedThrowingContinuation { continuation in
        artworkQueue.async {
            do {
                continuation.resume(returning: try artworkStore.read(name))
            } catch { // EXPECT: finding held-out-miss (concept: clean)
                continuation.resume(throwing: error)
            }
        }
    }
}

func validateCredential(_ credential: Data) async throws -> Identity {
    try await withCheckedThrowingContinuation { continuation in
        keychainQueue.async {
            do {
                continuation.resume(returning: try credentialVerifier.verifySignature(credential))
            } catch { // EXPECT: finding
                continuation.resume(throwing: error)
            }
        }
    }
}
