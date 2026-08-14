package sulis

import (
	"context"
	"encoding/base64"
	"strings"
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

// mustHash returns a validly-encoded argon2id PHC hash for tampering tests
// below, built with light params so hashing stays fast.
func mustHash(t *testing.T) string {
	t.Helper()
	hash, err := hashPassword("correct-horse-battery-staple", testArgon2Params)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	return hash
}

// tamperHash splits a PHC-format hash on "$", replaces the segment at index
// with replacement, and rejoins it.
func tamperHash(hash string, index int, replacement string) string {
	parts := strings.Split(hash, "$")
	parts[index] = replacement
	return strings.Join(parts, "$")
}

func TestDecodeHashRejectsWrongAlgorithm(t *testing.T) {
	tampered := tamperHash(mustHash(t), 1, "argon2i")

	_, err := verifyPassword("correct-horse-battery-staple", tampered)
	if err == nil {
		t.Fatal("expected error for wrong algorithm label")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}

func TestDecodeHashRejectsOversizedMemory(t *testing.T) {
	tampered := tamperHash(mustHash(t), 3, "m=4294967295,t=1,p=1")

	_, err := verifyPassword("correct-horse-battery-staple", tampered)
	if err == nil {
		t.Fatal("expected error for oversized memory parameter")
	}
	if !strings.Contains(err.Error(), "hash parameters out of bounds") {
		t.Fatalf("expected out of bounds error, got %v", err)
	}
}

func TestDecodeHashRejectsZeroParams(t *testing.T) {
	hash := mustHash(t)

	t.Run("ZeroIterations", func(t *testing.T) {
		tampered := tamperHash(hash, 3, "m=8192,t=0,p=1")

		_, err := verifyPassword("correct-horse-battery-staple", tampered)
		if err == nil {
			t.Fatal("expected error for zero iterations")
		}
	})

	t.Run("ZeroParallelism", func(t *testing.T) {
		tampered := tamperHash(hash, 3, "m=8192,t=1,p=0")

		_, err := verifyPassword("correct-horse-battery-staple", tampered)
		if err == nil {
			t.Fatal("expected error for zero parallelism")
		}
	})
}

func TestDecodeHashRejectsBadSaltOrKeySize(t *testing.T) {
	hash := mustHash(t)

	t.Run("ShortSalt", func(t *testing.T) {
		tampered := tamperHash(hash, 4, base64.RawStdEncoding.EncodeToString(make([]byte, 4)))

		_, err := verifyPassword("correct-horse-battery-staple", tampered)
		if err == nil {
			t.Fatal("expected error for undersized salt")
		}
	})

	t.Run("ShortKey", func(t *testing.T) {
		tampered := tamperHash(hash, 5, base64.RawStdEncoding.EncodeToString(make([]byte, 8)))

		_, err := verifyPassword("correct-horse-battery-staple", tampered)
		if err == nil {
			t.Fatal("expected error for undersized key/hash")
		}
	})
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, _, err := s.Register(ctx, "alice@example.com", "short12") // 7 bytes
	if err != ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestRegisterRejectsHugePassword(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	huge := strings.Repeat("a", 1025) // 1 byte over the default max
	_, _, err := s.Register(ctx, "alice@example.com", huge)
	if err != ErrPasswordTooLong {
		t.Fatalf("expected ErrPasswordTooLong, got %v", err)
	}
}

// TestPolicyAppliesToChangeSetInitialAndReset checks that the password
// length policy is enforced by ChangePassword, SetInitialPassword, and
// ResetPassword, and that a policy failure in ResetPassword does not consume
// the reset token.
func TestPolicyAppliesToChangeSetInitialAndReset(t *testing.T) {
	ctx := context.Background()
	const short = "short"

	t.Run("ChangePassword", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		user, _, err := s.Register(ctx, "alice@example.com", "good-password")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if err := s.ChangePassword(ctx, user.ID, "good-password", short); err != ErrPasswordTooShort {
			t.Fatalf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("SetInitialPassword", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com")
		if err != nil {
			t.Fatalf("CreateMagicLinkToken: %v", err)
		}
		// The user is only created at redemption time (deferred user creation).
		bob, _, err := s.RedeemMagicLink(ctx, rawToken)
		if err != nil {
			t.Fatalf("RedeemMagicLink: %v", err)
		}
		if err := s.SetInitialPassword(ctx, bob.ID, short); err != ErrPasswordTooShort {
			t.Fatalf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("ResetPassword", func(t *testing.T) {
		s, _, _, tokens := newTestEnv(WithArgon2Params(testArgon2Params))
		if _, _, err := s.Register(ctx, "carol@example.com", "good-password"); err != nil {
			t.Fatalf("Register: %v", err)
		}
		rawToken, err := s.CreatePasswordResetToken(ctx, "carol@example.com")
		if err != nil {
			t.Fatalf("CreatePasswordResetToken: %v", err)
		}

		if err := s.ResetPassword(ctx, rawToken, short); err != ErrPasswordTooShort {
			t.Fatalf("expected ErrPasswordTooShort, got %v", err)
		}

		// A policy rejection must not burn the token: it must still be
		// present and usable with a valid password.
		if len(tokens.tokens) != 1 {
			t.Fatalf("expected reset token to remain unconsumed, got %d tokens", len(tokens.tokens))
		}
		if err := s.ResetPassword(ctx, rawToken, "good-new-password"); err != nil {
			t.Fatalf("ResetPassword with valid password: %v", err)
		}
	})
}
