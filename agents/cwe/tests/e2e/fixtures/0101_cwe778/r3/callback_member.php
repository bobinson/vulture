<?php
// Feature 0101, CWE-778 Concept A, PHP (RED round 2 re-check). A call through a
// member or static chain that takes an anonymous function,
// `$this->db->transaction(function () use ($id) {`, declares nothing: the method
// above it is the routine. Every identifier is invented.
class RecordStore {
    public function revokeAllGrants($userId) {
        $this->db->transaction(function () use ($userId) {
            try {
                $this->store->deleteAll($userId);
            } catch (Exception $e) { // EXPECT: finding
                $this->lastError = $e;
            }
        });
    }

    public function revokeAllTokens($userId) {
        Db::transaction(function () use ($userId) {
            try {
                $this->store->deleteAll($userId);
            } catch (Exception $e) { // EXPECT: finding
                $this->lastError = $e;
            }
        });
    }

    public function compactPages($userId) {
        $this->db->transaction(function () use ($userId) {
            try {
                $this->store->deleteAll($userId);
            } catch (Exception $e) { // EXPECT: clean
                $this->lastError = $e;
            }
        });
    }
}
