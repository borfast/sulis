package totp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// testAESKeyA and testAESKeyB are two independent 32-byte (AES-256) keys.
// testAESKeyB stands in for a rotated-to replacement of testAESKeyA in the
// rotation tests below.
var (
	testAESKeyA = bytes.Repeat([]byte("A"), 32)
	testAESKeyB = bytes.Repeat([]byte("B"), 32)
)

func TestNewAESEncryptorRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewAESEncryptor(make([]byte, n)); err == nil {
			t.Fatalf("NewAESEncryptor accepted a %d-byte key, want an error (AES-256 requires exactly 32)", n)
		}
	}
}

func TestNewAESEncryptorRejectsWrongLengthRotatedKey(t *testing.T) {
	if _, err := NewAESEncryptor(testAESKeyA, make([]byte, 16)); err == nil {
		t.Fatal("NewAESEncryptor accepted a rotated key of the wrong length")
	}
}

// TestAESEncryptorRoundTrip pins the core property: what Encrypt returns is
// neither the plaintext nor does it contain it, and Decrypt recovers it
// exactly.
func TestAESEncryptorRoundTrip(t *testing.T) {
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}

	const secret = "JBSWY3DPEHPK3PXP"
	ciphertext, err := enc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ciphertext == secret || strings.Contains(ciphertext, secret) {
		t.Fatalf("ciphertext %q is or contains the plaintext secret %q", ciphertext, secret)
	}

	got, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Fatalf("Decrypt round trip = %q, want %q", got, secret)
	}
}

// TestAESEncryptorNonceIsRandomPerCall guards against a reused/fixed nonce,
// which would make GCM catastrophically break: two encryptions of the same
// secret must not be identical.
func TestAESEncryptorNonceIsRandomPerCall(t *testing.T) {
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	const secret = "JBSWY3DPEHPK3PXP"

	c1, err := enc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	c2, err := enc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if c1 == c2 {
		t.Fatal("encrypting the same secret twice produced identical ciphertexts; the nonce is not varying")
	}
}

// TestAESEncryptorDecryptsWithRotatedKey is the rotation scenario from the
// task brief: encrypt under key A, rotate to A+B (B current, A kept for
// decrypting what A already wrote), and confirm the old ciphertext still
// decrypts. It also confirms new encryptions actually move to the new key.
func TestAESEncryptorDecryptsWithRotatedKey(t *testing.T) {
	oldEnc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	ciphertext, err := oldEnc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	rotated, err := NewAESEncryptor(testAESKeyB, testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor (rotated): %v", err)
	}

	got, err := rotated.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt after rotation: %v", err)
	}
	if got != secret {
		t.Fatalf("Decrypt after rotation = %q, want %q", got, secret)
	}

	newCiphertext, err := rotated.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt after rotation: %v", err)
	}
	if _, err := oldEnc.Decrypt(newCiphertext); err == nil {
		t.Fatal("the pre-rotation encryptor decrypted ciphertext written under the new current key")
	}
}

// TestAESEncryptorWrongKeyFailsClosed is the fourth scenario from the task
// brief: a wrong key must fail with an error, never return garbage that
// looks like a plausible secret.
func TestAESEncryptorWrongKeyFailsClosed(t *testing.T) {
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	ciphertext, err := enc.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongKeyEnc, err := NewAESEncryptor(testAESKeyB)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}

	got, err := wrongKeyEnc.Decrypt(ciphertext)
	if err == nil {
		t.Fatalf("Decrypt with the wrong key succeeded and returned %q instead of failing closed", got)
	}
}

func TestAESEncryptorDecryptRejectsTamperedCiphertext(t *testing.T) {
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	ciphertext, err := enc.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := []byte(ciphertext)
	// Flip a byte in the middle of the payload rather than at either end,
	// where a base64 padding character could make the flip a no-op.
	tampered[len(tampered)/2] ^= 1
	if got, err := enc.Decrypt(string(tampered)); err == nil {
		t.Fatalf("Decrypt accepted tampered ciphertext and returned %q", got)
	}
}

func TestAESEncryptorDecryptRejectsTruncatedCiphertext(t *testing.T) {
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	ciphertext, err := enc.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for _, n := range []int{0, 1, 4, 8, 12, 16} {
		if n > len(ciphertext) {
			continue
		}
		if got, err := enc.Decrypt(ciphertext[:n]); err == nil {
			t.Fatalf("Decrypt accepted a ciphertext truncated to %d bytes and returned %q", n, got)
		}
	}
}

func TestAESEncryptorDecryptRejectsGarbageBase64(t *testing.T) {
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	if got, err := enc.Decrypt("not valid base64!!"); err == nil {
		t.Fatalf("Decrypt accepted a non-base64 string and returned %q", got)
	}
}

// TestServiceWithEncryptorStoresCiphertextNotPlaintext is the first
// scenario from the task brief: with an encryptor configured, the value
// reaching the store is neither the base32 secret nor does it contain it.
func TestServiceWithEncryptorStoresCiphertextNotPlaintext(t *testing.T) {
	store := newMemTOTPStore()
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	svc := mustService(t, store, "Example", WithEncryptor(enc))
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	pending, err := store.GetPendingTOTP(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if pending.Secret == secret {
		t.Fatal("the value reaching the store is the plaintext base32 secret")
	}
	if strings.Contains(pending.Secret, secret) {
		t.Fatal("the value reaching the store contains the plaintext base32 secret")
	}
}

// TestReplaceEnrollmentStoresCiphertextNotPlaintext is
// TestServiceWithEncryptorStoresCiphertextNotPlaintext's counterpart for the
// OTHER enrollment path. enroll's encryptSecret call sits ahead of the
// forceReplace branch, so ReplaceEnrollment is safe by construction today —
// but nothing pinned that fact, and a future split of Enroll/
// ReplaceEnrollment into two independent code paths could silently drop the
// encrypt call on one of them without any test catching it. This asserts
// the no-plaintext property against ReplaceEnrollment's own write
// (Store.ReplacePending), not just Enroll's (Store.EnrollPending).
func TestReplaceEnrollmentStoresCiphertextNotPlaintext(t *testing.T) {
	store := newMemTOTPStore()
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	svc := mustService(t, store, "Example", WithEncryptor(enc))
	ctx := context.Background()

	// Establish a verified, active credential first, so ReplaceEnrollment
	// is genuinely replacing something rather than enrolling from scratch.
	firstSecret, _, err := svc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	firstCode, err := svc.Generate(firstSecret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user-1", firstCode); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	secret, _, err := svc.ReplaceEnrollment(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("ReplaceEnrollment: %v", err)
	}

	pending, err := store.GetPendingTOTP(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if pending.Secret == secret {
		t.Fatal("the value reaching the store is the plaintext base32 secret")
	}
	if strings.Contains(pending.Secret, secret) {
		t.Fatal("the value reaching the store contains the plaintext base32 secret")
	}
}

// TestServiceWithEncryptorRoundTripsThroughEnrollConfirmValidate is the
// second scenario from the task brief: Enroll -> ConfirmEnrollment ->
// Validate all work with encryption on.
func TestServiceWithEncryptorRoundTripsThroughEnrollConfirmValidate(t *testing.T) {
	store := newMemTOTPStore()
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	svc := mustService(t, store, "Example", WithEncryptor(enc))
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user-1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	nextCode, err := svc.Generate(secret, time.Now().Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user-1", nextCode); err != nil {
		t.Fatalf("Validate after encrypted round trip: %v", err)
	}

	// The active credential's counter bump (Validate's SaveTOTP) must still
	// carry ciphertext, not the plaintext secret decrypted along the way.
	active, err := store.GetActiveTOTP(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetActiveTOTP: %v", err)
	}
	if active.Secret == secret || strings.Contains(active.Secret, secret) {
		t.Fatal("Validate's counter-bump save wrote the plaintext secret back to the store")
	}
}

// TestServiceWithoutEncryptorStoresPlaintext pins the documented default:
// no configured Encryptor means unchanged, plaintext behavior.
func TestServiceWithoutEncryptorStoresPlaintext(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "Example")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	pending, err := store.GetPendingTOTP(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if pending.Secret != secret {
		t.Fatalf("with no Encryptor configured, stored secret = %q, want the plaintext %q", pending.Secret, secret)
	}
}

// failingEncryptor is a minimal Encryptor test double that can be told to
// fail Encrypt and/or Decrypt on demand, so Service's own error-propagation
// paths (encryptSecret/decryptSecret) can be exercised directly, rather
// than only indirectly via AESEncryptor's specific failure modes (wrong
// key, tampered ciphertext). A zero-value failingEncryptor round-trips via
// a fixed prefix, so it behaves like a real Encryptor when no failure is
// configured.
type failingEncryptor struct {
	encryptErr error
	decryptErr error
}

func (f *failingEncryptor) Encrypt(plaintext string) (string, error) {
	if f.encryptErr != nil {
		return "", f.encryptErr
	}
	return "ciphertext:" + plaintext, nil
}

func (f *failingEncryptor) Decrypt(ciphertext string) (string, error) {
	if f.decryptErr != nil {
		return "", f.decryptErr
	}
	return strings.TrimPrefix(ciphertext, "ciphertext:"), nil
}

var (
	errTestEncryptFailure = errors.New("test: encryptor refused to encrypt")
	errTestDecryptFailure = errors.New("test: encryptor refused to decrypt")
)

// TestServiceEnrollFailsClosedWhenEncryptFails pins encryptSecret's own
// error-propagation branch: if the configured Encryptor cannot encrypt,
// Enroll must fail rather than falling back to storing the plaintext.
func TestServiceEnrollFailsClosedWhenEncryptFails(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "Example", WithEncryptor(&failingEncryptor{encryptErr: errTestEncryptFailure}))

	if _, _, err := svc.Enroll(context.Background(), "user-1", "user1@example.com"); err == nil {
		t.Fatal("Enroll succeeded despite the configured Encryptor failing to encrypt")
	}
}

// TestServiceConfirmEnrollmentFailsClosedWhenDecryptFails and
// TestServiceValidateFailsClosedWhenDecryptFails are the Service-level
// counterparts to TestAESEncryptorWrongKeyFailsClosed: a Service whose
// Encryptor cannot decrypt an already-stored secret (e.g. because its key
// no longer matches what the secret was encrypted under) must fail the
// operation, never silently compare a code against garbage or treat the
// user as unenrolled.
func TestServiceConfirmEnrollmentFailsClosedWhenDecryptFails(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "Example", WithEncryptor(&failingEncryptor{}))
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	broken := mustService(t, store, "Example", WithEncryptor(&failingEncryptor{decryptErr: errTestDecryptFailure}))
	err = broken.ConfirmEnrollment(ctx, "user-1", code)
	if err == nil {
		t.Fatal("ConfirmEnrollment succeeded despite the configured Encryptor failing to decrypt")
	}
	if errors.Is(err, ErrTOTPNotEnrolled) || errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("ConfirmEnrollment reported a decrypt failure as %v; it must be distinguishable from a semantic rejection", err)
	}
}

func TestServiceValidateFailsClosedWhenDecryptFails(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "Example", WithEncryptor(&failingEncryptor{}))
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user-1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	nextCode, err := svc.Generate(secret, time.Now().Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	broken := mustService(t, store, "Example", WithEncryptor(&failingEncryptor{decryptErr: errTestDecryptFailure}))
	err = broken.Validate(ctx, "user-1", nextCode)
	if err == nil {
		t.Fatal("Validate succeeded despite the configured Encryptor failing to decrypt")
	}
	if errors.Is(err, ErrTOTPInvalid) || errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("Validate reported a decrypt failure as %v; it must be distinguishable from a semantic rejection", err)
	}
}

// TestConfirmEnrollmentFailsClosedOnPreEncryptorPlaintextRow and
// TestValidateFailsClosedOnPreEncryptorPlaintextRow cover the realistic
// migration scenario this package does NOT support silently: a row written
// while no Encryptor was configured (the default), read back later by a
// Service that now has one configured (WithEncryptor turned on for the
// first time on an existing deployment).
//
// AESEncryptor.Decrypt was NOT changed for this — it already fails closed
// on this input, for one of two reasons depending on secret length: (1) a
// stored secret whose base32-encoded length isn't a multiple of 4 fails
// outright at base64 decoding; (2) a stored secret long enough that its
// base32 alphabet (A-Z2-7, a subset of base64's) happens to decode as valid
// base64 anyway (true for the default 20-byte/32-character secret size)
// gets its first 8 "bytes" looked up as a key-ID fingerprint that was never
// registered by any configured key, so it fails via errUnknownKeyID. Either
// way, Decrypt returns a non-nil error rather than ever treating an
// unrecognized value as if it were already plaintext. These tests exist so
// that property stays true if AESEncryptor's internals ever change, and so
// the behavior is pinned rather than left to be rediscovered by an operator
// enabling encryption for the first time. See the README's "Encrypting
// stored secrets" section and the T506 Decisions row for the documented
// recovery path (re-enrollment).
func TestConfirmEnrollmentFailsClosedOnPreEncryptorPlaintextRow(t *testing.T) {
	store := newMemTOTPStore()
	ctx := context.Background()

	// Seed a pending enrollment the old way: no Encryptor configured.
	plainSvc := mustService(t, store, "Example")
	secret, _, err := plainSvc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := plainSvc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Confirm that same enrollment through a Service pointed at the same
	// store, but now with an Encryptor configured — the "just turned
	// encryption on" moment.
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	encryptedSvc := mustService(t, store, "Example", WithEncryptor(enc))

	err = encryptedSvc.ConfirmEnrollment(ctx, "user-1", code)
	if err == nil {
		t.Fatal("ConfirmEnrollment succeeded against a pre-encryption plaintext row; it must fail closed instead")
	}
	if errors.Is(err, ErrTOTPNotEnrolled) || errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("ConfirmEnrollment reported the pre-encryption row's decrypt failure as %v; it must be distinguishable from a semantic rejection", err)
	}
}

func TestValidateFailsClosedOnPreEncryptorPlaintextRow(t *testing.T) {
	store := newMemTOTPStore()
	ctx := context.Background()

	// Seed a fully active credential the old way: no Encryptor configured.
	plainSvc := mustService(t, store, "Example")
	secret, _, err := plainSvc.Enroll(ctx, "user-1", "user1@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := plainSvc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := plainSvc.ConfirmEnrollment(ctx, "user-1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	// Validate that same active credential through a Service pointed at the
	// same store, but now with an Encryptor configured. The submitted code
	// doesn't matter — decryption must fail before it is ever compared.
	enc, err := NewAESEncryptor(testAESKeyA)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	encryptedSvc := mustService(t, store, "Example", WithEncryptor(enc))

	anyCode, err := plainSvc.Generate(secret, time.Now().Add(time.Duration(plainSvc.cfg.Period)*time.Second))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	err = encryptedSvc.Validate(ctx, "user-1", anyCode)
	if err == nil {
		t.Fatal("Validate succeeded against a pre-encryption plaintext row; it must fail closed instead")
	}
	if errors.Is(err, ErrTOTPInvalid) || errors.Is(err, ErrTOTPReplayed) || errors.Is(err, ErrTOTPNotEnrolled) || errors.Is(err, ErrTOTPNotVerified) {
		t.Fatalf("Validate reported the pre-encryption row's decrypt failure as %v; it must be distinguishable from a semantic rejection", err)
	}
}
