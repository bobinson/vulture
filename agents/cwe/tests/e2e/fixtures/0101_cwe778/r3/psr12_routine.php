<?php
// Feature 0101, CWE-778 Concept A, PHP PSR-12 (RED round 2, R2-1, R2-9).
// PSR-12 puts a method's `{` on its own line: the declaration above it is the
// routine. `$this->x = $e` is a field store (LLD 5.1.2), a hand-off like the
// `return [...]` twin. Every identifier is invented.

namespace App\Records;

class RecordStore
{
    public function revokeAllSessions($userId)
    {
        try {
            $this->store->deleteAll($userId);
        } catch (\Exception $e) { // EXPECT: finding
            return ['ok' => false, 'error' => $e];
        }
    }

    public function revokeAllGrants($userId) {
        try {
            $this->store->deleteAll($userId);
        } catch (\Exception $e) { // EXPECT: finding
            return ['ok' => false, 'error' => $e];
        }
    }

    public function refreshThumbnails($userId)
    {
        try {
            $this->store->deleteAll($userId);
        } catch (\Exception $e) { // EXPECT: clean
            return ['ok' => false, 'error' => $e];
        }
    }

    public function refreshCounters($id)
    {
        try {
            $this->store->load($id);
        } catch (\Exception $e) { // EXPECT: clean
            $this->lastError = $e;
        }
    }

    public function revokeTokens($id)
    {
        try {
            $this->store->load($id);
        } catch (\Exception $e) { // EXPECT: finding
            $this->lastError = $e;
        }
    }
}
