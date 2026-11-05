<?php
// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// The failure errors a DeferredFuture, so the code awaiting its future receives it.
// Every identifier is invented.
// HELD-OUT-TOKENS: DeferredFuture

final class ThumbnailJob
{
    public function run(DeferredFuture $deferred, string $path): void
    {
        try {
            $deferred->complete($this->scaler->scale($path));
        } catch (\Throwable $e) { // EXPECT: finding held-out-miss (concept: clean)
            $deferred->error($e);
        }
    }

    public function checkSignature(DeferredFuture $deferred, string $signed): void
    {
        try {
            $deferred->complete($this->signer->verifySignature($signed));
        } catch (\Throwable $e) { // EXPECT: finding
            $deferred->error($e);
        }
    }
}
