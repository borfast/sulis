// Package totp implements TOTP (RFC 6238) with zero external dependencies.
//
// It supports generating and validating time-based one-time passwords using
// HMAC-SHA1, HMAC-SHA256, or HMAC-SHA512. It also generates otpauth:// URIs
// for use with authenticator apps.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	// HMAC-SHA1 is the RFC 6238 default and the only algorithm every
	// authenticator app supports. SHA-1 collision attacks do not affect HMAC,
	// so this use is sound; SHA-256 and SHA-512 are offered as options.
	"crypto/sha1" // #nosec G505 -- required by RFC 6238; HMAC-SHA1 is unaffected by SHA-1 collisions
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strings"
	"time"
)

var (
	ErrTOTPInvalid     = errors.New("totp: invalid code")
	ErrTOTPNotEnrolled = errors.New("totp: not enrolled")
	ErrTOTPNotVerified = errors.New("totp: enrollment not verified")
	ErrTOTPReplayed    = errors.New("totp: code already used")
	ErrTOTPRateLimited = errors.New("totp: rate limited")

	// ErrTOTPAlreadyEnrolled is returned by Enroll when the user already
	// has an active (verified) TOTP credential. Enroll refuses outright
	// rather than silently overwriting a working second factor — see
	// Enroll's GoDoc and ReplaceEnrollment for the explicit path to
	// supersede one on purpose.
	ErrTOTPAlreadyEnrolled = errors.New("totp: already enrolled")
)

// Limiter enforces a rate limit for a caller-supplied key. It is declared
// separately from (and identical to) the root package's Limiter interface so
// this package has no dependency on the root module; a single implementation
// satisfies both via structural typing. Allow returns a non-nil error if the
// key should be denied.
type Limiter interface {
	Allow(ctx context.Context, key string) error
}

// Algorithm identifies the HMAC hash algorithm.
type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota // default, most widely supported
	AlgorithmSHA256
	AlgorithmSHA512
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

func (a Algorithm) hash() func() hash.Hash {
	switch a {
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// Config holds TOTP generation parameters.
type Config struct {
	Issuer     string    // e.g. "MyApp"
	Algorithm  Algorithm // default: SHA1
	Digits     int       // default: 6
	Period     uint64    // seconds, default: 30
	Skew       uint      // number of periods to check before/after current (default: 1)
	SecretSize int       // bytes of entropy for new secrets (default: 20)
	Limiter    Limiter   // rate limiter consulted before validating a code (default: nil, disabled)

	// Encryptor, if set, encrypts every secret before it reaches Store and
	// decrypts it immediately after reading one back — see WithEncryptor.
	// Default: nil, meaning NO ENCRYPTION. Credential.Secret then reaches
	// Store as the same base32 plaintext this package has always written,
	// which is NOT safe for a production deployment of a real second
	// factor: a leaked store yields every enrolled secret, usable
	// indefinitely and silently, with no work factor standing between the
	// leak and every account it can now generate valid codes for.
	//
	// Turning this on for the first time on an existing deployment does
	// NOT retroactively encrypt rows already on file, and does not read
	// them as plaintext either: ConfirmEnrollment/Validate's decryptSecret
	// call fails closed against a pre-Encryptor row (a decode or unknown
	// key-ID error — AESEncryptor never mistakes an unrecognized value for
	// its own plaintext), so that enrollment simply stops working. The
	// recovery path is re-enrollment, not a migration step this package
	// performs for you — see the README's "Encrypting stored secrets".
	Encryptor Encryptor
}

// Option is a functional option for configuring the TOTP service.
type Option func(*Config)

// WithAlgorithm sets the HMAC algorithm.
func WithAlgorithm(a Algorithm) Option {
	return func(c *Config) { c.Algorithm = a }
}

// WithDigits sets the number of digits in the code (6 or 8).
func WithDigits(d int) Option {
	return func(c *Config) { c.Digits = d }
}

// WithPeriod sets the time step in seconds.
func WithPeriod(p uint64) Option {
	return func(c *Config) { c.Period = p }
}

// WithSkew sets the number of periods to check before and after the current one.
func WithSkew(s uint) Option {
	return func(c *Config) { c.Skew = s }
}

// WithSecretSize sets the number of random bytes for new secrets.
func WithSecretSize(n int) Option {
	return func(c *Config) { c.SecretSize = n }
}

// WithLimiter sets the rate limiter consulted before Validate or
// ConfirmEnrollment checks a code, keyed by "totp:"+userID — the 10^6 code
// space (or smaller, for 6-digit codes) is guessable without one. A nil
// limiter (the default) disables rate limiting.
func WithLimiter(l Limiter) Option {
	return func(c *Config) { c.Limiter = l }
}

// WithEncryptor configures the Encryptor Service uses to protect every
// secret before it reaches Store and immediately after reading one back:
// Enroll, ReplaceEnrollment, ConfirmEnrollment, and Validate's counter-bump
// save all go through it, so a Store implementation never receives, stores,
// or reads back a usable secret — the protection does not depend on the
// store author. See AESEncryptor for the AES-256-GCM implementation this
// package provides, including key rotation.
//
// The default is nil: no encryption, so Credential.Secret reaches Store as
// plaintext, exactly as before this option existed. Configure a real
// Encryptor before relying on this package for a production second factor.
func WithEncryptor(e Encryptor) Option {
	return func(c *Config) { c.Encryptor = e }
}

// Service manages TOTP enrollment and validation.
type Service struct {
	store Store
	cfg   Config
}

// NewService creates a new TOTP service.
func NewService(store Store, issuer string, opts ...Option) (*Service, error) {
	cfg := Config{
		Issuer:     issuer,
		Algorithm:  AlgorithmSHA1,
		Digits:     6,
		Period:     30,
		Skew:       1,
		SecretSize: 20,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	switch {
	case cfg.Issuer == "" || strings.Contains(cfg.Issuer, ":"):
		return nil, fmt.Errorf("totp: issuer must be non-empty and contain no ':'")
	case cfg.Digits < 6 || cfg.Digits > 8:
		return nil, fmt.Errorf("totp: digits must be 6-8, got %d", cfg.Digits)
	case cfg.Period < 15 || cfg.Period > 300:
		return nil, fmt.Errorf("totp: period must be 15-300 seconds, got %d", cfg.Period)
	case cfg.Skew > 4:
		return nil, fmt.Errorf("totp: skew must be at most 4, got %d", cfg.Skew)
	case cfg.SecretSize < 16:
		return nil, fmt.Errorf("totp: secret size must be at least 16 bytes, got %d", cfg.SecretSize)
	}

	return &Service{store: store, cfg: cfg}, nil
}

// Enroll generates a new TOTP secret for the user and returns the
// base32-encoded secret and an otpauth:// URI suitable for QR code
// generation. The enrollment is stored as pending — not active, so
// Validate will not accept codes for it — until ConfirmEnrollment verifies
// the first code.
//
// Enroll refuses with ErrTOTPAlreadyEnrolled if the user already has an
// active (verified) TOTP credential. A single stray call — a
// double-submitted form, a CSRF'd POST, a retried request — must not be
// able to silently replace a working second factor with an unconfirmed
// one; use ReplaceEnrollment when the caller explicitly intends to
// supersede an existing factor.
//
// Enrollment changes a security-relevant setting for the account: callers
// should gate this endpoint behind recent re-authentication —
// sulis.Sulis.RequireRecentAuth against the caller's session, refreshed via
// sulis.Sulis.ReAuthenticate — rather than a bare session.
func (s *Service) Enroll(ctx context.Context, userID, accountName string) (secret, uri string, err error) {
	return s.enroll(ctx, userID, accountName, false)
}

// ReplaceEnrollment generates a new TOTP secret for the user and stores it
// as a pending enrollment, exactly like Enroll — except it succeeds even
// when the user already has an active (verified) TOTP credential. This is
// the explicit "I mean to replace my existing factor" path: the existing
// active credential is left completely untouched, and Validate keeps
// accepting codes for it, until ConfirmEnrollment verifies a code for the
// new secret and promotes it.
//
// Enrollment changes a security-relevant setting for the account: callers
// should gate this endpoint behind recent re-authentication —
// sulis.Sulis.RequireRecentAuth against the caller's session, refreshed via
// sulis.Sulis.ReAuthenticate — rather than a bare session.
func (s *Service) ReplaceEnrollment(ctx context.Context, userID, accountName string) (secret, uri string, err error) {
	return s.enroll(ctx, userID, accountName, true)
}

// enroll implements both Enroll (forceReplace=false) and ReplaceEnrollment
// (forceReplace=true): the two differ only in which Store method they use
// to guard (or not) against an existing active credential.
func (s *Service) enroll(ctx context.Context, userID, accountName string, forceReplace bool) (secret, uri string, err error) {
	secretBytes := make([]byte, s.cfg.SecretSize)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("totp: generating secret: %w", err)
	}

	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	storedSecret, err := s.encryptSecret(secret)
	if err != nil {
		return "", "", err
	}

	cred := &Credential{
		ID:        generateID(),
		UserID:    userID,
		Secret:    storedSecret,
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if forceReplace {
		if err := s.store.ReplacePending(ctx, cred); err != nil {
			return "", "", err
		}
	} else {
		if err := s.store.EnrollPending(ctx, cred); err != nil {
			return "", "", err
		}
	}

	uri = buildOTPAuthURI(s.cfg.Issuer, accountName, secret, s.cfg)
	return secret, uri, nil
}

// ConfirmEnrollment verifies a code against the user's pending enrollment
// and, if it matches, atomically promotes that enrollment to the active
// credential Validate checks codes against (Store.ConfirmEnrollment).
//
// ConfirmEnrollment returns ErrTOTPNotEnrolled — the same as if nothing
// were pending at all — in two distinct situations callers must not
// conflate:
//
//  1. Racing enrollment: the pending enrollment was superseded by a
//     concurrent Enroll or ReplaceEnrollment between the read here and the
//     promotion, so the code that was validated no longer names anything
//     current to promote.
//  2. Retry of an already-succeeded confirm: this is also the common case
//     in practice — a double-submitted confirmation form, or an HTTP
//     response dropped after the server already committed the promotion.
//     Once a pending enrollment is promoted, its slot is consumed exactly
//     once (mirroring the single-use contract ConsumeToken/ConsumeChallenge
//     place on their own resources); a second call with the same code
//     finds no pending enrollment left and returns ErrTOTPNotEnrolled even
//     though the user genuinely is enrolled and the first call's factor is
//     active and working.
//
// Because of (2), an HTTP layer built on this must not render
// ErrTOTPNotEnrolled from ConfirmEnrollment as "you are not enrolled" —
// check the user's current enrollment status (e.g. via GetActiveTOTP)
// before deciding how to react to a confirm retry, rather than trusting
// the error alone.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) error {
	if err := s.allow(ctx, "totp:"+userID); err != nil {
		return err
	}

	pending, err := s.store.GetPendingTOTP(ctx, userID)
	if err != nil {
		return ErrTOTPNotEnrolled
	}

	plainSecret, err := s.decryptSecret(pending.Secret)
	if err != nil {
		// Not the same failure as "nothing pending": the enrollment is
		// right there, but the configured Encryptor could not recover its
		// secret (wrong/missing key, corrupted ciphertext). Surface it
		// distinctly rather than telling the caller there is nothing to
		// confirm, matching Validate's SaveTOTP failure, which is returned
		// unchanged for the same reason.
		return err
	}

	counter, ok := s.matchCode(plainSecret, code, time.Now())
	if !ok {
		return ErrTOTPInvalid
	}

	if _, err := s.store.ConfirmEnrollment(ctx, userID, pending.ID, counter); err != nil {
		return ErrTOTPNotEnrolled
	}
	return nil
}

// Validate checks a TOTP code for an enrolled, verified user. It returns nil
// if and only if the code is valid; every rejection reason is a distinct,
// non-nil error, so callers that only branch on `err != nil` reject a wrong
// code correctly instead of treating a (false, nil)-shaped "not valid, but
// no error" result as success.
//
// To prevent replay, a code is only accepted once: its time-step counter
// must be strictly greater than the last accepted counter for this
// credential. Reusing a previously accepted code (or an older one, once a
// newer counter has been accepted) returns ErrTOTPReplayed, distinguishable
// from a wrong code (ErrTOTPInvalid) via errors.Is.
func (s *Service) Validate(ctx context.Context, userID, code string) error {
	if err := s.allow(ctx, "totp:"+userID); err != nil {
		return err
	}

	cred, err := s.store.GetActiveTOTP(ctx, userID)
	if err != nil {
		// No active credential. Distinguish "never enrolled at all" from
		// "enrolled, but the only enrollment on file is still pending
		// confirmation" so callers get a distinct, actionable error
		// either way; a pending enrollment never lets Validate succeed
		// (see Store's active/pending separation).
		if _, pendingErr := s.store.GetPendingTOTP(ctx, userID); pendingErr == nil {
			return ErrTOTPNotVerified
		}
		return ErrTOTPNotEnrolled
	}

	plainSecret, err := s.decryptSecret(cred.Secret)
	if err != nil {
		// Same reasoning as ConfirmEnrollment's identical check: a decrypt
		// failure is not "wrong code" or "not enrolled", it's this
		// instance's Encryptor being unable to recover a secret that
		// genuinely exists. cred.Secret itself is left untouched below, so
		// this never risks writing anything back.
		return err
	}

	counter, ok := s.matchCode(plainSecret, code, time.Now())
	if !ok {
		return ErrTOTPInvalid
	}
	if counter <= cred.LastUsedCounter {
		return ErrTOTPReplayed
	}

	// cred.Secret is left exactly as read from the store — still whatever
	// encryptSecret produced at enrollment time — so this save never writes
	// plainSecret (or anything derived from it) back to Store.
	cred.LastUsedCounter = counter
	if err := s.store.SaveTOTP(ctx, cred); err != nil {
		// Fail closed: if we can't persist the counter, we can't guarantee
		// the code won't be replayed, so don't accept it.
		return err
	}
	return nil
}

// Unenroll removes TOTP enrollment for a user.
func (s *Service) Unenroll(ctx context.Context, userID string) error {
	return s.store.DeleteTOTP(ctx, userID)
}

// Generate produces the current TOTP code for the given base32-encoded secret.
// This is useful for testing; in production, the authenticator app generates codes.
func (s *Service) Generate(secret string, t time.Time) (string, error) {
	return generateCode(secret, t, s.cfg)
}

// allow consults the configured rate limiter for key, if one is set. A nil
// limiter is a no-op. Any error from the limiter is normalized to
// ErrTOTPRateLimited so callers never leak limiter implementation details.
func (s *Service) allow(ctx context.Context, key string) error {
	if s.cfg.Limiter == nil {
		return nil
	}
	if err := s.cfg.Limiter.Allow(ctx, key); err != nil {
		return ErrTOTPRateLimited
	}
	return nil
}

// encryptSecret returns secret ready to hand to a Store-writing method:
// unchanged if no Encryptor is configured (the default — see WithEncryptor),
// or its ciphertext otherwise. Every path that writes Credential.Secret
// (enroll, Validate's counter-bump save) MUST go through this rather than
// writing secret directly, or a configured Encryptor is silently bypassed
// and the plaintext still reaches the store.
func (s *Service) encryptSecret(secret string) (string, error) {
	if s.cfg.Encryptor == nil {
		return secret, nil
	}
	ciphertext, err := s.cfg.Encryptor.Encrypt(secret)
	if err != nil {
		return "", fmt.Errorf("totp: encrypting secret: %w", err)
	}
	return ciphertext, nil
}

// decryptSecret reverses encryptSecret: unchanged if no Encryptor is
// configured, otherwise the plaintext recovered from stored's ciphertext.
// Every path that reads Credential.Secret before comparing it to a
// submitted code (ConfirmEnrollment, Validate) MUST go through this. It
// fails closed: any Decrypt error propagates unchanged rather than being
// treated as "not encrypted after all" and compared as-is.
func (s *Service) decryptSecret(stored string) (string, error) {
	if s.cfg.Encryptor == nil {
		return stored, nil
	}
	plaintext, err := s.cfg.Encryptor.Decrypt(stored)
	if err != nil {
		return "", fmt.Errorf("totp: decrypting secret: %w", err)
	}
	return plaintext, nil
}

// matchCode checks a code against the secret, allowing for clock skew, and
// returns the time-step counter of the matched window.
func (s *Service) matchCode(secret, code string, t time.Time) (counter uint64, ok bool) {
	for i := -int(s.cfg.Skew); i <= int(s.cfg.Skew); i++ {
		// NewService validates Period to 15..300, so the widening below cannot
		// overflow time.Duration's int64.
		shifted := t.Add(time.Duration(i) * time.Duration(s.cfg.Period) * time.Second) // #nosec G115 -- Period validated to 15..300 in NewService
		expected, err := generateCode(secret, shifted, s.cfg)
		if err != nil {
			continue
		}
		if subtle(code, expected) {
			shiftedCounter, ok := counterAt(shifted, s.cfg.Period)
			if !ok {
				continue
			}
			return shiftedCounter, true
		}
	}
	return 0, false
}

// counterAt returns the RFC 6238 time-step counter for t, reporting false for
// times before the Unix epoch, where the counter is undefined. Callers must
// pass a period validated as non-zero (NewService enforces 15..300).
func counterAt(t time.Time, period uint64) (uint64, bool) {
	secs := t.Unix()
	if secs < 0 {
		return 0, false
	}
	return uint64(secs) / period, true
}

// generateCode implements the TOTP algorithm per RFC 6238.
func generateCode(secret string, t time.Time, cfg Config) (string, error) {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(secret),
	)
	if err != nil {
		return "", fmt.Errorf("totp: decoding secret: %w", err)
	}

	counter, ok := counterAt(t, cfg.Period)
	if !ok {
		return "", fmt.Errorf("totp: time %s precedes the Unix epoch", t)
	}

	// Encode counter as 8-byte big-endian.
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// HMAC
	mac := hmac.New(cfg.Algorithm.hash(), secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.4).
	offset := sum[len(sum)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	// Modulo to get the desired number of digits.
	mod := uint32(math.Pow10(cfg.Digits))
	code := binCode % mod

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", cfg.Digits), code), nil
}

// subtle performs a constant-time string comparison.
func subtle(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range len(a) {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// buildOTPAuthURI constructs an otpauth:// URI for authenticator apps.
func buildOTPAuthURI(issuer, account, secret string, cfg Config) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", cfg.Algorithm.String())
	v.Set("digits", fmt.Sprintf("%d", cfg.Digits))
	v.Set("period", fmt.Sprintf("%d", cfg.Period))

	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
