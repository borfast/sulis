package sulis

import (
	"context"
	"time"

	"github.com/borfast/sulis/passwordcheck"
)

// Limiter enforces a rate limit for a caller-supplied key. Implementations
// decide the algorithm, window, and storage (e.g. a token bucket backed by
// Redis or an in-memory store). Allow returns a non-nil error if the key
// should be denied.
type Limiter interface {
	Allow(ctx context.Context, key string) error
}

// PasswordChecker screens a candidate password for known-compromised values,
// beyond what the length policy can judge. It is consulted on every path that
// sets a password — Register, ChangePassword, ResetPassword,
// SetInitialPassword — and never on a path that merely verifies one; see
// WithPasswordChecker.
//
// Check receives the password in its NFKC-normalized form, which is exactly
// the string that will be hashed and stored. It returns nil if the password
// is acceptable, ErrPasswordCompromised (or an error wrapping it) to reject
// it, and any other error if it could not reach a verdict — that last case
// propagates to the caller unchanged and must not be presented to a user as
// "your password is compromised", because nobody actually looked.
//
// Implementations must be safe for concurrent use. This is the same method
// set as passwordcheck.Checker, so the checkers in that package satisfy it
// directly and so does anything written against either interface.
type PasswordChecker interface {
	Check(ctx context.Context, password string) error
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
	MinPasswordLength              int           // minimum accepted password length in bytes (default: 12)
	MaxPasswordLength              int           // maximum accepted password length in bytes (default: 1024)
	Argon2                         Argon2Params
	Limiter                        Limiter         // rate limiter consulted at guessable choke points (default: an in-process MemoryLimiter)
	PasswordChecker                PasswordChecker // screens new passwords for known-compromised values (default: passwordcheck.NewBlocklist())

	// FailureLockoutThreshold, FailureLockoutBaseBackoff, and
	// FailureLockoutMaxBackoff configure the optional automatic-lockout
	// mechanism (see WithFailureLockout). FailureLockoutThreshold of 0
	// (the default) disables it entirely: VerifyPassword never writes
	// FailedLoginAttempts or LockedUntil.
	FailureLockoutThreshold   int
	FailureLockoutBaseBackoff time.Duration
	FailureLockoutMaxBackoff  time.Duration

	// IdleTimeout, if positive, is how long a session may go unused before
	// ValidateSession rejects it with ErrSessionExpired — independent of,
	// and typically much shorter than, SessionDuration. Zero (the default)
	// disables idle expiry entirely: sessions live until SessionDuration
	// regardless of use. See WithIdleTimeout.
	IdleTimeout time.Duration
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
		MinPasswordLength:              12,
		MaxPasswordLength:              1024,
		Limiter:                        NewMemoryLimiter(),
		PasswordChecker:                passwordcheck.NewBlocklist(),
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
//
// The bytes counted are those of the NFKC-normalized password (see
// normalizePassword), because that is the string Argon2 actually consumes.
// Normalization can shorten a password — twelve fullwidth digits are 36 raw
// bytes and 12 normalized ones — so measuring the raw form would let a
// password through a minimum it does not actually meet.
//
// The default minimum is 12. It was 8 before this series; NIST SP 800-63B
// treats 8 as the floor for a memorized secret and expects more from anything
// that is not backed by a second factor, and this series was already breaking
// the API. Lowering it is supported and sometimes right — a deployment where
// every account has a passkey or TOTP, for instance — and doing so makes the
// embedded blocklist (see WithPasswordChecker) matter far more, since most
// common passwords are shorter than 12 characters and are otherwise rejected
// by this policy before the checker ever sees them.
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

// WithIdleTimeout enables idle expiry: a session unused for longer than d is
// rejected by ValidateSession with ErrSessionExpired, even if its absolute
// SessionDuration lifetime has not yet elapsed. "Unused" is tracked via
// Session.LastSeenAt/IdleExpiresAt, refreshed by ValidateSession on a
// throttled cadence (see sessionTouchInterval in session.go) rather than on
// every single call — the idle deadline can therefore lag true last-use by
// up to that interval, which trades a small amount of precision for not
// writing to the session store on every authenticated request.
//
// Passing d <= 0 disables idle expiry — the default, so a Sulis built with
// no options never checks or writes IdleExpiresAt at all.
func WithIdleTimeout(d time.Duration) Option {
	return func(c *Config) { c.IdleTimeout = d }
}

// WithPasswordChecker replaces the checker consulted on every password-setting
// path — Register, ChangePassword, ResetPassword, SetInitialPassword — after
// the length policy passes and before the password is hashed. A checker that
// returns ErrPasswordCompromised rejects the password; any other error is an
// operational failure and propagates to the caller unchanged.
//
// The default is passwordcheck.NewBlocklist(), an embedded corpus of the ten
// thousand most common passwords: no network, no third party, nothing to
// configure, and on by default because a check that has to be discovered in
// documentation mostly does not run. To also query Have I Been Pwned, compose
// rather than replace — passing the HIBP checker alone silently drops the
// local blocklist:
//
//	sulis.WithPasswordChecker(passwordcheck.All(
//		passwordcheck.NewBlocklist(),
//		passwordcheck.NewHIBP(),
//	))
//
// Passing nil disables password checking entirely, which is the right call
// only when something outside sulis already screens passwords.
//
// The checker is deliberately NOT consulted by VerifyPassword, Login, or
// ReAuthenticate. Screening at verification time would lock out every
// existing user whose password happens to be in the corpus the moment one is
// added or refreshed — turning a hardening change into a mass outage, and
// worse, one whose only remedy (a password reset) is itself a login-adjacent
// flow. A password is screened where it is chosen, not where it is proven.
// Applications that want existing users moved off a now-known-bad password
// should detect that out of band and require a change, which keeps the user
// in control of when it happens.
func WithPasswordChecker(c PasswordChecker) Option {
	return func(cfg *Config) { cfg.PasswordChecker = c }
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
