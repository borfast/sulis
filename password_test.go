package sulis

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerifyPassword(t *testing.T) {
	params := defaultConfig().Argon2
	password := "correct-horse-battery-staple"

	hash, err := hashPassword(password, params, nil)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	// Correct password should verify.
	ok, _, err := verifyPassword(password, hash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("verifyPassword returned false for correct password")
	}

	// Wrong password should not verify.
	ok, _, err = verifyPassword("wrong-password", hash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Fatal("verifyPassword returned true for wrong password")
	}
}

func TestHashUniqueSalts(t *testing.T) {
	params := defaultConfig().Argon2
	h1, _ := hashPassword("same-password", params, nil)
	h2, _ := hashPassword("same-password", params, nil)
	if h1 == h2 {
		t.Fatal("two hashes of the same password should differ (different salts)")
	}
}

func TestDecodeHashInvalid(t *testing.T) {
	_, _, err := verifyPassword("anything", "not-a-valid-hash", nil)
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}

// mustHash returns a validly-encoded argon2id PHC hash for tampering tests
// below, built with light params so hashing stays fast.
func mustHash(t *testing.T) string {
	t.Helper()
	hash, err := hashPassword("correct-horse-battery-staple", testArgon2Params, nil)
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

	_, _, err := verifyPassword("correct-horse-battery-staple", tampered, nil)
	if err == nil {
		t.Fatal("expected error for wrong algorithm label")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}

func TestDecodeHashRejectsOversizedMemory(t *testing.T) {
	tampered := tamperHash(mustHash(t), 3, "m=4294967295,t=1,p=1")

	_, _, err := verifyPassword("correct-horse-battery-staple", tampered, nil)
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

		_, _, err := verifyPassword("correct-horse-battery-staple", tampered, nil)
		if err == nil {
			t.Fatal("expected error for zero iterations")
		}
	})

	t.Run("ZeroParallelism", func(t *testing.T) {
		tampered := tamperHash(hash, 3, "m=8192,t=1,p=0")

		_, _, err := verifyPassword("correct-horse-battery-staple", tampered, nil)
		if err == nil {
			t.Fatal("expected error for zero parallelism")
		}
	})
}

func TestDecodeHashRejectsBadSaltOrKeySize(t *testing.T) {
	hash := mustHash(t)

	t.Run("ShortSalt", func(t *testing.T) {
		tampered := tamperHash(hash, 4, base64.RawStdEncoding.EncodeToString(make([]byte, 4)))

		_, _, err := verifyPassword("correct-horse-battery-staple", tampered, nil)
		if err == nil {
			t.Fatal("expected error for undersized salt")
		}
	})

	t.Run("ShortKey", func(t *testing.T) {
		tampered := tamperHash(hash, 5, base64.RawStdEncoding.EncodeToString(make([]byte, 8)))

		_, _, err := verifyPassword("correct-horse-battery-staple", tampered, nil)
		if err == nil {
			t.Fatal("expected error for undersized key/hash")
		}
	})
}

// TestNeedsRehash covers needsRehash's cost-dimension comparison in
// isolation, decoupled from any Sulis/Login plumbing. Sulis-level coverage
// (a real weak-hash-gets-upgraded-on-login flow) lives in sulis_test.go.
func TestNeedsRehash(t *testing.T) {
	const password = "correct-horse-battery-staple"
	weak := Argon2Params{Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16}
	strong := Argon2Params{Memory: 16, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16}

	weakHash, err := hashPassword(password, weak, nil)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	strongHash, err := hashPassword(password, strong, nil)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	t.Run("LessMemoryNeedsRehash", func(t *testing.T) {
		if !needsRehash(weakHash, strong) {
			t.Fatal("a hash using less memory than configured must need a rehash")
		}
	})

	t.Run("FewerIterationsNeedsRehash", func(t *testing.T) {
		sameMemoryFewerIterations := Argon2Params{Memory: strong.Memory, Iterations: 1, Parallelism: strong.Parallelism, SaltLength: 16, KeyLength: 16}
		h, err := hashPassword(password, sameMemoryFewerIterations, nil)
		if err != nil {
			t.Fatalf("hashPassword: %v", err)
		}
		if !needsRehash(h, strong) {
			t.Fatal("a hash using fewer iterations than configured must need a rehash")
		}
	})

	t.Run("LessParallelismNeedsRehash", func(t *testing.T) {
		sameCostLessParallel := Argon2Params{Memory: strong.Memory, Iterations: strong.Iterations, Parallelism: 1, SaltLength: 16, KeyLength: 16}
		twiceParallel := Argon2Params{Memory: strong.Memory, Iterations: strong.Iterations, Parallelism: 2, SaltLength: 16, KeyLength: 16}
		h, err := hashPassword(password, sameCostLessParallel, nil)
		if err != nil {
			t.Fatalf("hashPassword: %v", err)
		}
		if !needsRehash(h, twiceParallel) {
			t.Fatal("a hash using less parallelism than configured must need a rehash")
		}
	})

	// TestNeedsRehash/HigherMemoryButFewerIterationsStillNeedsRehash pins the
	// OR-not-AND rule explicitly: needsRehash must trigger if the stored hash
	// is weaker in ANY single cost dimension, even when it is simultaneously
	// stronger in another. A hash with more memory but fewer iterations than
	// configured is not "on balance stronger" — it is weaker in the
	// dimension that matters (an attacker's brute-force cost is bounded by
	// the weakest dimension actually used), so it must still be upgraded.
	t.Run("HigherMemoryButFewerIterationsStillNeedsRehash", func(t *testing.T) {
		moreMemoryFewerIterations := Argon2Params{Memory: strong.Memory * 2, Iterations: 1, Parallelism: strong.Parallelism, SaltLength: 16, KeyLength: 16}
		h, err := hashPassword(password, moreMemoryFewerIterations, nil)
		if err != nil {
			t.Fatalf("hashPassword: %v", err)
		}
		if !needsRehash(h, strong) {
			t.Fatal("a hash with more memory but fewer iterations than configured must still need a rehash — needsRehash is an OR across dimensions, not an AND")
		}
	})

	t.Run("EqualParamsDoNotNeedRehash", func(t *testing.T) {
		if needsRehash(strongHash, strong) {
			t.Fatal("a hash already at the configured params must not need a rehash")
		}
	})

	t.Run("StrongerStoredParamsDoNotNeedRehash", func(t *testing.T) {
		if needsRehash(strongHash, weak) {
			t.Fatal("a hash stronger than configured must not need a rehash")
		}
	})

	t.Run("MalformedHashDoesNotNeedRehash", func(t *testing.T) {
		if needsRehash("not-a-valid-hash", strong) {
			t.Fatal("a hash that fails to decode must not be reported as needing a rehash — verifyPassword already rejects it")
		}
	})
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, _, _, err := s.Register(ctx, "alice@example.com", "short12", RequestInfo{}) // 7 bytes
	if err != ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestRegisterRejectsHugePassword(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	huge := strings.Repeat("a", 1025) // 1 byte over the default max
	_, _, _, err := s.Register(ctx, "alice@example.com", huge, RequestInfo{})
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
		user, _, _, err := s.Register(ctx, "alice@example.com", "good-password", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if err := s.ChangePassword(ctx, user.ID, "good-password", short, RequestInfo{}); err != ErrPasswordTooShort {
			t.Fatalf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("SetInitialPassword", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
		if err != nil {
			t.Fatalf("CreateMagicLinkToken: %v", err)
		}
		// The user is only created at redemption time (deferred user creation).
		bob, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
		if err != nil {
			t.Fatalf("RedeemMagicLink: %v", err)
		}
		if err := s.SetInitialPassword(ctx, bob.ID, short); err != ErrPasswordTooShort {
			t.Fatalf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("ResetPassword", func(t *testing.T) {
		s, _, _, tokens := newTestEnv(WithArgon2Params(testArgon2Params))
		if _, _, _, err := s.Register(ctx, "carol@example.com", "good-password", RequestInfo{}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		rawToken, err := s.CreatePasswordResetToken(ctx, "carol@example.com", RequestInfo{})
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

// legacyHash builds a PHC-format argon2id hash of the *raw* bytes of
// password, deliberately skipping the NFKC normalization hashPassword
// applies (T505). It reproduces a hash written by a pre-T505 sulis, which is
// the only way to test the compatibility path from inside a tree where
// hashPassword always normalizes.
//
// Kept deliberately close to hashPassword's body: if that function's PHC
// assembly ever changes, this must change with it or the fixture stops
// representing a real stored hash.
func legacyHash(t *testing.T, password string, params Argon2Params) string {
	t.Helper()
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generating salt: %v", err)
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func TestNormalizePassword(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"already normal", nfkcComposedForm, nfkcComposedForm},
		{"decomposed folds onto composed", nfkcDecomposedForm, nfkcComposedForm},
		{"ligature expands", nfkcCompatibilityForm, nfkcCompatibilityNFKC},
		{"ascii is untouched", "correct-battery-staple", "correct-battery-staple"},
		{"empty is untouched", "", ""},
		{"invalid utf-8 is passed through unchanged", "\xff\xfe-passphrase", "\xff\xfe-passphrase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePassword(tc.input); got != tc.want {
				t.Fatalf("normalizePassword(%q) = %q, want %q", tc.input, got, tc.want)
			}
			// NFKC is idempotent, and everything downstream (double
			// normalization in hashPassword after checkPasswordPolicy has
			// already normalized, for one) relies on that.
			if got := normalizePassword(normalizePassword(tc.input)); got != tc.want {
				t.Fatalf("normalizePassword is not idempotent for %q", tc.input)
			}
		})
	}
}

// TestHashPasswordNormalizes pins the core of the T505 change: hashing is
// defined over the NFKC form of a password, not over the bytes the caller
// happened to hand in. Without it, whether a password verifies depends on
// which keyboard or platform produced the composition — a silent lockout for
// anyone whose password contains a character with more than one spelling.
func TestHashPasswordNormalizes(t *testing.T) {
	hash, err := hashPassword(nfkcDecomposedForm, testArgon2Params, nil)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	for _, tc := range []struct {
		name     string
		password string
	}{
		{"the form that was hashed", nfkcDecomposedForm},
		{"the NFKC-equivalent composed form", nfkcComposedForm},
	} {
		ok, legacy, err := verifyPassword(tc.password, hash, nil)
		if err != nil {
			t.Fatalf("%s: verifyPassword: %v", tc.name, err)
		}
		if !ok {
			t.Fatalf("%s: does not verify against a hash of an NFKC-equivalent form", tc.name)
		}
		if legacy {
			t.Fatalf("%s: reported as a pre-normalization match, but the stored hash is already normalized", tc.name)
		}
	}
}

// TestVerifyPasswordFallsBackToThePreNormalizationForm is the compatibility
// half of the NFKC change. A hash written before T505 was derived from the
// raw bytes the user typed. If verification only ever compared the NFKC form,
// every such user whose password is not already NFKC-normal would be locked
// out of their own account with an ordinary "invalid credentials" and no
// route back in short of a password reset.
func TestVerifyPasswordFallsBackToThePreNormalizationForm(t *testing.T) {
	stored := legacyHash(t, nfkcCompatibilityForm, testArgon2Params)

	ok, legacy, err := verifyPassword(nfkcCompatibilityForm, stored, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("a password stored before NFKC normalization no longer verifies against the form it was typed in")
	}
	if !legacy {
		t.Fatal("the match was not reported as a pre-normalization one, so nothing upstream can know to upgrade the stored hash")
	}
}

// TestVerifyPasswordFallbackAcceptsNoPasswordItDidNotAcceptBefore is the
// security statement that makes the fallback safe: it can only ever match
// the exact bytes the stored hash was derived from, so it widens nothing.
func TestVerifyPasswordFallbackAcceptsNoPasswordItDidNotAcceptBefore(t *testing.T) {
	stored := legacyHash(t, nfkcCompatibilityForm, testArgon2Params)

	// The NFKC form is a *different* string from the one that was hashed, so
	// it must not verify against a legacy hash of the ligature form. (It
	// starts working once a successful login rehashes the stored value; see
	// TestLegacyPasswordHashIsUpgradedToTheNormalizedFormOnLogin.)
	ok, _, err := verifyPassword(nfkcCompatibilityNFKC, stored, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Fatal("the expanded form verified against a hash of the ligature form; the fallback compares raw bytes and must not")
	}

	ok, _, err = verifyPassword("totally-different-password", stored, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Fatal("an unrelated password verified through the pre-normalization fallback")
	}
}

// TestVerifyPasswordSkipsTheFallbackForANormalPassword pins the cost story:
// an already-NFKC-normal password (every ASCII password, so nearly all of
// them) must never pay for a second Argon2 comparison, because there is no
// second form to compare.
func TestVerifyPasswordSkipsTheFallbackForANormalPassword(t *testing.T) {
	stored := legacyHash(t, "correct-battery-staple", testArgon2Params)
	ok, legacy, err := verifyPassword("correct-battery-staple", stored, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("an ASCII password does not verify against a pre-T505 hash of itself; normalization must be a no-op for it")
	}
	if legacy {
		t.Fatal("an ASCII password matched through the pre-normalization fallback; its normalized and raw forms are identical, so the primary comparison must have matched")
	}
}

// legacyHashWithPepper is legacyHash with a pepper folded in via the same
// HMAC-SHA256 transform hashPassword applies (applyPepper). It simulates a
// hash written by a pre-T505 sulis (raw bytes, not NFKC-normalized) that
// nonetheless already had a pepper configured when it was written — the
// fixture TestVerifyPasswordWithPepperStillUsesTheNFKCFallback needs to
// prove the pepper composes with T505's legacy-fallback seam rather than
// requiring a second one.
func legacyHashWithPepper(t *testing.T, password string, params Argon2Params, pepper []byte) string {
	t.Helper()
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generating salt: %v", err)
	}
	hash := argon2.IDKey(applyPepper(password, pepper), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// TestHashAndVerifyPasswordWithPepper pins the basic property: hashing and
// verifying under the same configured pepper works exactly like the
// no-pepper path already tested by TestHashAndVerifyPassword.
func TestHashAndVerifyPasswordWithPepper(t *testing.T) {
	pepper := []byte("a-configured-pepper-value")
	password := "correct-horse-battery-staple"

	hash, err := hashPassword(password, testArgon2Params, pepper)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	ok, _, err := verifyPassword(password, hash, pepper)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("verifyPassword returned false for the correct password under the same pepper")
	}

	ok, _, err = verifyPassword("wrong-password", hash, pepper)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Fatal("verifyPassword returned true for the wrong password")
	}
}

// TestPepperChangesTheDerivedHash is the mutation-guard for peppering
// actually taking part in what gets hashed: hashes of the same password
// under different peppers (including no pepper at all) must not cross verify.
func TestPepperChangesTheDerivedHash(t *testing.T) {
	password := "correct-horse-battery-staple"

	noPepper, err := hashPassword(password, testArgon2Params, nil)
	if err != nil {
		t.Fatalf("hashPassword (no pepper): %v", err)
	}
	withPepperA, err := hashPassword(password, testArgon2Params, []byte("pepper-a"))
	if err != nil {
		t.Fatalf("hashPassword (pepper A): %v", err)
	}
	withPepperB, err := hashPassword(password, testArgon2Params, []byte("pepper-b"))
	if err != nil {
		t.Fatalf("hashPassword (pepper B): %v", err)
	}

	if ok, _, _ := verifyPassword(password, noPepper, []byte("pepper-a")); ok {
		t.Fatal("a hash produced with no pepper verified under a configured one")
	}
	if ok, _, _ := verifyPassword(password, withPepperA, nil); ok {
		t.Fatal("a hash produced with a pepper verified with no pepper")
	}
	if ok, _, _ := verifyPassword(password, withPepperA, []byte("pepper-b")); ok {
		t.Fatal("a hash produced with pepper A verified under pepper B")
	}

	for _, tc := range []struct {
		name   string
		hash   string
		pepper []byte
	}{
		{"no pepper", noPepper, nil},
		{"pepper A", withPepperA, []byte("pepper-a")},
		{"pepper B", withPepperB, []byte("pepper-b")},
	} {
		ok, _, err := verifyPassword(password, tc.hash, tc.pepper)
		if err != nil {
			t.Fatalf("%s: verifyPassword: %v", tc.name, err)
		}
		if !ok {
			t.Fatalf("%s: hash did not verify under its own pepper", tc.name)
		}
	}
}

// TestVerifyPasswordCannotVerifyAPrePepperHashOnceAPepperIsConfigured pins
// the migration story WithPepper documents: a pepper introduced onto a
// running deployment cannot verify a hash written before it existed. There
// is no dual-path fallback the way T505 built for NFKC normalization — see
// the T506 Decisions row for why building one here is not the same problem.
func TestVerifyPasswordCannotVerifyAPrePepperHashOnceAPepperIsConfigured(t *testing.T) {
	password := "correct-horse-battery-staple"
	prePepperHash, err := hashPassword(password, testArgon2Params, nil)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	ok, _, err := verifyPassword(password, prePepperHash, []byte("pepper-introduced-later"))
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Fatal("a hash written before a pepper existed verified once a pepper was configured; the migration story says this must not happen")
	}
}

// TestVerifyPasswordWithPepperStillUsesTheNFKCFallback proves the pepper
// composes correctly with T505's pre-normalization fallback when the SAME
// pepper was already in effect when the legacy (raw-bytes) hash was
// written: peppering applies to whichever candidate form the existing seam
// already tries (normalized, then raw), rather than needing a second path.
func TestVerifyPasswordWithPepperStillUsesTheNFKCFallback(t *testing.T) {
	pepper := []byte("a-configured-pepper-value")
	stored := legacyHashWithPepper(t, nfkcCompatibilityForm, testArgon2Params, pepper)

	ok, legacy, err := verifyPassword(nfkcCompatibilityForm, stored, pepper)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("a pre-normalization hash written under a pepper does not verify against the exact form it was typed in, under the same pepper")
	}
	if !legacy {
		t.Fatal("the match was not reported as a pre-normalization one")
	}
}
