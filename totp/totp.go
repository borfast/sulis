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
	"crypto/sha1"
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
)

// Algorithm identifies the HMAC hash algorithm.
type Algorithm int

const (
	AlgorithmSHA1   Algorithm = iota // default, most widely supported
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
	Issuer    string    // e.g. "MyApp"
	Algorithm Algorithm // default: SHA1
	Digits    int       // default: 6
	Period    uint64    // seconds, default: 30
	Skew      uint      // number of periods to check before/after current (default: 1)
	SecretSize int      // bytes of entropy for new secrets (default: 20)
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

// Service manages TOTP enrollment and validation.
type Service struct {
	store Store
	cfg   Config
}

// NewService creates a new TOTP service.
func NewService(store Store, issuer string, opts ...Option) *Service {
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
	return &Service{store: store, cfg: cfg}
}

// Enroll generates a new TOTP secret for the user and returns the base32-encoded
// secret and an otpauth:// URI suitable for QR code generation.
// The enrollment is not active until ConfirmEnrollment is called.
func (s *Service) Enroll(ctx context.Context, userID, accountName string) (secret, uri string, err error) {
	secretBytes := make([]byte, s.cfg.SecretSize)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("totp: generating secret: %w", err)
	}

	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	cred := &Credential{
		ID:        generateID(),
		UserID:    userID,
		Secret:    secret,
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if err := s.store.SaveTOTP(ctx, cred); err != nil {
		return "", "", err
	}

	uri = buildOTPAuthURI(s.cfg.Issuer, accountName, secret, s.cfg)
	return secret, uri, nil
}

// ConfirmEnrollment verifies the first TOTP code to confirm enrollment.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) error {
	cred, err := s.store.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return ErrTOTPNotEnrolled
	}

	counter, ok := s.matchCode(cred.Secret, code, time.Now())
	if !ok {
		return ErrTOTPInvalid
	}

	cred.Verified = true
	cred.LastUsedCounter = counter
	return s.store.SaveTOTP(ctx, cred)
}

// Validate checks a TOTP code for an enrolled, verified user.
//
// To prevent replay, a code is only accepted once: its time-step counter
// must be strictly greater than the last accepted counter for this
// credential. Reusing a previously accepted code (or an older one, once a
// newer counter has been accepted) returns ErrTOTPReplayed.
func (s *Service) Validate(ctx context.Context, userID, code string) (bool, error) {
	cred, err := s.store.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return false, ErrTOTPNotEnrolled
	}
	if !cred.Verified {
		return false, ErrTOTPNotVerified
	}

	counter, ok := s.matchCode(cred.Secret, code, time.Now())
	if !ok {
		return false, nil
	}
	if counter <= cred.LastUsedCounter {
		return false, ErrTOTPReplayed
	}

	cred.LastUsedCounter = counter
	if err := s.store.SaveTOTP(ctx, cred); err != nil {
		// Fail closed: if we can't persist the counter, we can't guarantee
		// the code won't be replayed, so don't accept it.
		return false, err
	}
	return true, nil
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

// matchCode checks a code against the secret, allowing for clock skew, and
// returns the time-step counter of the matched window.
func (s *Service) matchCode(secret, code string, t time.Time) (counter uint64, ok bool) {
	for i := -int(s.cfg.Skew); i <= int(s.cfg.Skew); i++ {
		shifted := t.Add(time.Duration(i) * time.Duration(s.cfg.Period) * time.Second)
		expected, err := generateCode(secret, shifted, s.cfg)
		if err != nil {
			continue
		}
		if subtle(code, expected) {
			return uint64(shifted.Unix()) / s.cfg.Period, true
		}
	}
	return 0, false
}

// generateCode implements the TOTP algorithm per RFC 6238.
func generateCode(secret string, t time.Time, cfg Config) (string, error) {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(secret),
	)
	if err != nil {
		return "", fmt.Errorf("totp: decoding secret: %w", err)
	}

	counter := uint64(t.Unix()) / cfg.Period

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
