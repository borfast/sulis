package sulis

import "time"

// Argon2Params holds the parameters for argon2id password hashing.
type Argon2Params struct {
	Memory      uint32 // memory in KiB (default: 64 * 1024)
	Iterations  uint32 // time parameter (default: 3)
	Parallelism uint8  // threads (default: 2)
	SaltLength  uint32 // bytes (default: 16)
	KeyLength   uint32 // bytes (default: 32)
}

// Config holds the configuration for a Sulis instance.
type Config struct {
	SessionDuration                time.Duration // how long sessions are valid (default: 24h)
	TokenDuration                  time.Duration // how long reset/magic link tokens are valid (default: 1h)
	TwoFactorTokenDuration         time.Duration // how long two-factor pending-login tokens are valid (default: 5m)
	EmailVerificationTokenDuration time.Duration // how long email verification tokens are valid (default: 24h)
	SessionTokenBytes              int           // length of random session tokens in bytes (default: 32)
	ResetTokenBytes                int           // length of random reset/magic link tokens in bytes (default: 32)
	RevokeSessionsOnPasswordChange bool          // revoke all sessions when a password is changed or reset (default: true)
	MinPasswordLength              int           // minimum accepted password length in bytes (default: 8)
	MaxPasswordLength              int           // maximum accepted password length in bytes (default: 1024)
	Argon2                         Argon2Params
}

// Option is a functional option for configuring Sulis.
type Option func(*Config)

func defaultConfig() Config {
	return Config{
		SessionDuration:                24 * time.Hour,
		TokenDuration:                  1 * time.Hour,
		TwoFactorTokenDuration:         5 * time.Minute,
		EmailVerificationTokenDuration: 24 * time.Hour,
		SessionTokenBytes:              32,
		ResetTokenBytes:                32,
		RevokeSessionsOnPasswordChange: true,
		MinPasswordLength:              8,
		MaxPasswordLength:              1024,
		Argon2: Argon2Params{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

// WithSessionDuration sets how long sessions remain valid.
func WithSessionDuration(d time.Duration) Option {
	return func(c *Config) { c.SessionDuration = d }
}

// WithTokenDuration sets how long password reset and magic link tokens remain valid.
func WithTokenDuration(d time.Duration) Option {
	return func(c *Config) { c.TokenDuration = d }
}

// WithTwoFactorTokenDuration sets how long two-factor pending-login tokens
// remain valid.
func WithTwoFactorTokenDuration(d time.Duration) Option {
	return func(c *Config) { c.TwoFactorTokenDuration = d }
}

// WithEmailVerificationTokenDuration sets how long email verification tokens
// remain valid.
func WithEmailVerificationTokenDuration(d time.Duration) Option {
	return func(c *Config) { c.EmailVerificationTokenDuration = d }
}

// WithArgon2Params sets custom argon2id parameters for password hashing.
func WithArgon2Params(p Argon2Params) Option {
	return func(c *Config) { c.Argon2 = p }
}

// WithRevokeSessionsOnPasswordChange controls whether all of a user's
// sessions are revoked when their password is changed or reset (default: true).
func WithRevokeSessionsOnPasswordChange(revoke bool) Option {
	return func(c *Config) { c.RevokeSessionsOnPasswordChange = revoke }
}

// WithPasswordLengthLimits sets the minimum and maximum accepted password
// length. Both bounds are measured in bytes (len(password)), not runes or
// characters — deliberately, to bound Argon2's input size regardless of
// encoding, so multi-byte UTF-8 passwords count for more than one unit per
// character.
func WithPasswordLengthLimits(minLength, maxLength int) Option {
	return func(c *Config) {
		c.MinPasswordLength = minLength
		c.MaxPasswordLength = maxLength
	}
}
