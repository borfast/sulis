package sulis

import (
	"testing"
)

func TestGenerateRawToken(t *testing.T) {
	raw, hash, err := generateRawToken(32)
	if err != nil {
		t.Fatalf("generateRawToken: %v", err)
	}

	if len(raw) != 64 { // 32 bytes = 64 hex chars
		t.Fatalf("expected raw token length 64, got %d", len(raw))
	}

	// Hash should match re-hashing the raw token.
	if got := hashToken(raw); got != hash {
		t.Fatal("hashToken does not match the hash returned by generateRawToken")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	h1 := hashToken("test-token-123")
	h2 := hashToken("test-token-123")
	if h1 != h2 {
		t.Fatal("hashToken should be deterministic")
	}
}

func TestHashTokenDifferentInputs(t *testing.T) {
	h1 := hashToken("token-a")
	h2 := hashToken("token-b")
	if h1 == h2 {
		t.Fatal("different tokens should produce different hashes")
	}
}
