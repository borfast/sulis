package sulis

import (
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	params := defaultConfig().Argon2
	password := "correct-horse-battery-staple"

	hash, err := hashPassword(password, params)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	// Correct password should verify.
	ok, err := verifyPassword(password, hash)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("verifyPassword returned false for correct password")
	}

	// Wrong password should not verify.
	ok, err = verifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Fatal("verifyPassword returned true for wrong password")
	}
}

func TestHashUniqueSalts(t *testing.T) {
	params := defaultConfig().Argon2
	h1, _ := hashPassword("same-password", params)
	h2, _ := hashPassword("same-password", params)
	if h1 == h2 {
		t.Fatal("two hashes of the same password should differ (different salts)")
	}
}

func TestDecodeHashInvalid(t *testing.T) {
	_, err := verifyPassword("anything", "not-a-valid-hash")
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}
