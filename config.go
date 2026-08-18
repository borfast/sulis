package sulis

import (
	"context"
	"time"
)

// Limiter enforces a rate limit for a caller-supplied key. Implementations
// decide the algorithm, window, and storage (e.g. a token bucket backed by
// Redis or an in-memory store). Allow returns a non-nil error if the key
// should be denied.
type Limiter interface {
	Allow(ctx context.Context, key string) error
}

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
	RequireVerifiedEmail           bool          // block new sessions for unverified accounts (default: true)
	MinPasswordLength              int           // minimum accepted password length in bytes (default: 8)
	MaxPasswordLength              int           // maximum accepted password length in bytes (default: 1024)
	Argon2                         Argon2Params
	Limiter                        Limiter // rate limiter consulted at guessable choke points (default: an in-process MemoryLimiter)

	// FailureLockoutThreshold, FailureLockoutBaseBackoff, and
	// FailureLockoutMaxBackoff configure the optional automatic-lockout
	// mechanism (see WithFailureLockout). FailureLockoutThreshold of 0
	// (the default) disables it entirely: VerifyPassword never writes
	// FailedLoginAttempts or LockedUntil.
	FailureLockoutThreshold   int
	FailureLockoutBaseBackoff time.Duration
	FailureLockoutMaxBackoff  time.Duration
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
		RequireVerifiedEmail:           true,
		MinPasswordLength:              8,
		MaxPasswordLength:              1024,
		Limiter:                        NewMemoryLimiter(),
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

// WithRequireVerifiedEmail sets whether new sessions are blocked until the
// account's email is verified. Register's signup session and magic-link
// redemption (which verifies the email itself) are always exempt.
func WithRequireVerifiedEmail(require bool) Option {
	return func(c *Config) { c.RequireVerifiedEmail = require }
}

// WithLimiter replaces the rate limiter consulted at guessable authentication
// choke points: password verification, and password reset / magic link token
// issuance. The default is an in-process MemoryLimiter; supply a shared
// implementation (Redis or similar) when running more than one instance, since
// the default enforces its budget per process.
//
// Passing nil disables rate limiting, but prefer WithoutRateLimiting, which
// says so in code.
func WithLimiter(l Limiter) Option {
	return func(c *Config) { c.Limiter = l }
}

// WithFailureLockout enables automatic, temporary lockout after threshold
// consecutive wrong passwords for one account. Once threshold is reached,
// VerifyPassword sets User.LockedUntil to baseBackoff after the moment of
// the triggering failure; every further wrong password while still locked
// pushes LockedUntil out again, doubling the backoff each time, up to
// maxBackoff. The lockout — and the failure count behind it — clears itself
// automatically the next time a correct password verifies outside the
// window, OR the account's password is successfully changed or reset
// (ChangePassword, ResetPassword, SetInitialPassword) — proving control of
// the account well enough to set a new password is at least as strong an
// identity proof as the login password itself. There is no explicit unlock
// call for either path. DisableUser/EnableUser remain available for an
// operator-initiated block, which is a distinct, unrelated mechanism that
// none of the above clears — a password reset lifts an automatic lockout,
// never a manual disable; only EnableUser does that (see the README's
// "Account disable and lockout" section).
//
// Default: disabled (threshold 0), so a Sulis built with no options never
// writes FailedLoginAttempts or LockedUntil, and VerifyPassword's normal
// path pays no extra store round trip.
//
// Off by default deliberately: this locks out the legitimate account owner
// exactly as effectively as it locks out an attacker, so an attacker who
// merely knows (or guesses) an email address can weaponize it as a
// denial-of-service against that account — a failure mode the rate limiter
// (on by default; see WithLimiter/MemoryLimiter) does not share, since it
// throttles the guesser without touching the account's own ability to log
// in once its window passes. Enable this only if your threat model needs an
// escalating response beyond rate limiting, and prefer a long baseBackoff/
// maxBackoff pair over a short one: the whole point is to make continued
// guessing expensive without approaching a permanent lock a legitimate
// owner could not eventually recover from on their own.
func WithFailureLockout(threshold int, baseBackoff, maxBackoff time.Duration) Option {
	return func(c *Config) {
		c.FailureLockoutThreshold = threshold
		c.FailureLockoutBaseBackoff = baseBackoff
		c.FailureLockoutMaxBackoff = maxBackoff
	}
}

// WithoutRateLimiting disables rate limiting entirely.
//
// Rate limiting is on by default because a library that has to ask for it in
// its documentation mostly runs without it. Turning it off should therefore be
// a visible, greppable line in your code rather than the consequence of not
// writing one — for instance when an upstream gateway already enforces limits.
func WithoutRateLimiting() Option {
	return func(c *Config) { c.Limiter = nil }
}
