package model

import "testing"

func TestGenerateAPIKey_HasCorrectFormat(t *testing.T) {
	key, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) < 40 {
		t.Fatalf("key too short: %s", key)
	}
	if key[:3] != "vk_" {
		t.Fatalf("expected vk_ prefix: %s", key)
	}
	if len(hash) == 0 {
		t.Fatal("empty hash")
	}
}

func TestVerifyAPIKey_MatchesHash(t *testing.T) {
	key, hash, _ := GenerateAPIKey()
	if !VerifyAPIKey(key, hash) {
		t.Fatal("should verify matching key")
	}
	if VerifyAPIKey("vk_wrong", hash) {
		t.Fatal("should reject wrong key")
	}
}

func TestAPIKeyPrefix_StableForSameKey(t *testing.T) {
	key, _, _ := GenerateAPIKey()
	p1 := APIKeyPrefix(key)
	p2 := APIKeyPrefix(key)
	if p1 != p2 || len(p1) != 10 {
		t.Fatalf("prefix unstable or wrong length: %s %s", p1, p2)
	}
}
