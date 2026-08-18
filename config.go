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

// TokenSource controls which channel(s) Authenticate accepts a session
// token from. See WithTokenSource.
type TokenSource int

const (
	// TokenSourceBoth accepts either an Authorization: Bearer header or the
	// configured session cookie — today's behavior, and the default.
	//
	// This stays the default even though this package now ships cookie
	// support (SessionCookie) and CSRF defenses (RequireSameOrigin,
	// RequireCSRFToken) in the same task that introduced this type: a
	// Bearer header is never attached to a request automatically by a
	// browser, so accepting one alongside a cookie does not create or
	// widen a CSRF exposure by itself — that exposure comes entirely from
	// the cookie channel, and is exactly what RequireSameOrigin/
	// RequireCSRFToken exist to close. Narrowing the default to
	// TokenSourceCookieOnly would break every existing Bearer-only
	// consumer for no CSRF benefit, since Bearer was never the risk.
	// See the T507 Decisions row in PROGRESS.md.
	TokenSourceBoth TokenSource = iota
	// TokenSourceCookieOnly rejects an Authorization: Bearer header
	// entirely — Authenticate never even reads it — and honors only the
	// configured session cookie.
	TokenSourceCookieOnly
	// TokenSourceBearerOnly rejects the session cookie entirely —
	// Authenticate never even reads it — and honors only an Authorization:
	// Bearer header. A deployment that sets this, and never calls
	// SessionCookie, needs neither RequireSameOrigin nor the CSRF helpers:
	// without a cookie there is no ambient credential for a forged
	// cross-site request to ride on.
	TokenSourceBearerOnly
)

// Config holds the configuration for a Sulis instance.
type Config struct {
	SessionDuration time.Duration // how long sessions are valid (default: 24h)
	TokenDuration   time.Duration // how long password reset tokens are valid (default: 1h)
	// MagicLinkDuration is how long magic-link tokens are valid (default:
	// 15m), independent of TokenDuration — see WithMagicLinkDuration.
	MagicLinkDuration              time.Duration
	TwoFactorTokenDuration         time.Duration // how long two-factor pending-login tokens are valid (default: 5m)
	EmailVerificationTokenDuration time.Duration // how long email verification tokens are valid (default: 24h)
	SessionTokenBytes              int           // length of random session tokens in bytes (default: 32)
	ResetTokenBytes                int           // length of random reset/magic link tokens in bytes (default: 32)
	RevokeSessionsOnPasswordChange bool          // revoke all sessions when a password is changed or reset (default: true)
	RequireVerifiedEmail           bool          // block new sessions for unverified accounts (default: true)
	// MagicLinkBinding requires RedeemMagicLink to be called with the
	// bindingNonce CreateMagicLinkToken returned alongside the token
	// (default: true) — see WithMagicLinkBinding.
	MagicLinkBinding  bool
	MinPasswordLength int // minimum accepted password length in bytes (default: 12)
	MaxPasswordLength int // maximum accepted password length in bytes (default: 1024)
	Argon2            Argon2Params
	Limiter           Limiter         // rate limiter consulted at guessable choke points (default: an in-process MemoryLimiter)
	PasswordChecker   PasswordChecker // screens new passwords for known-compromised values (default: passwordcheck.NewBlocklist())

	// Pepper is mixed into every password via HMAC-SHA256 before Argon2 —
	// see WithPepper. Default: nil, meaning no pepper.
	Pepper []byte

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

	// CookieName is the name Authenticate reads the session token from
	// (when TokenSource permits a cookie) and SessionCookie/
	// ClearSessionCookie set (default: "__Host-session"). See
	// WithCookieName.
	CookieName string

	// TokenSource controls which channel(s) Authenticate accepts a session
	// token from (default: TokenSourceBoth). See WithTokenSource.
	TokenSource TokenSource

	// EventSink receives security events — every security-relevant
	// decision this package makes. Default: nil, meaning nothing is
	// emitted. See WithEventSink and events.go.
	EventSink EventSink
}

// Option is a functional option for configuring Sulis.
type Option func(*Config)

// defaultCookieName is CookieName's default. The __Host- prefix is a
// browser-enforced guarantee that this cookie can only have been set by
// this exact origin, over HTTPS, for the whole origin (Path=/, no Domain)
// — SessionCookie/ClearSessionCookie always set Secure and Path=/ and
// never set Domain, regardless of CookieName, so that guarantee holds for
// any name carrying the prefix, including a custom one set via
// WithCookieName. See the T507 Decisions row in PROGRESS.md for why this
// is enforced by construction (nothing in this package's configuration
// surface can produce a Domain attribute) rather than by validating the
// combination at runtime.
const defaultCookieName = "__Host-session"

func defaultConfig() Config {
	return Config{
		SessionDuration:                24 * time.Hour,
		TokenDuration:                  1 * time.Hour,
		MagicLinkDuration:              15 * time.Minute,
		TwoFactorTokenDuration:         5 * time.Minute,
		EmailVerificationTokenDuration: 24 * time.Hour,
		SessionTokenBytes:              32,
		ResetTokenBytes:                32,
		RevokeSessionsOnPasswordChange: true,
		RequireVerifiedEmail:           true,
		MagicLinkBinding:               true,
		MinPasswordLength:              12,
		MaxPasswordLength:              1024,
		Limiter:                        NewMemoryLimiter(),
		PasswordChecker:                passwordcheck.NewBlocklist(),
		CookieName:                     defaultCookieName,
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

// WithTokenDuration sets how long password reset tokens remain valid.
// Magic-link tokens do NOT use this — they have their own, independent
// duration; see WithMagicLinkDuration.
func WithTokenDuration(d time.Duration) Option {
	return func(c *Config) { c.TokenDuration = d }
}

// WithMagicLinkDuration sets how long magic-link tokens remain valid
// (default: 15m). This is independent of TokenDuration/WithTokenDuration,
// which governs password-reset tokens only: a magic link is a full
// credential delivered in cleartext over email — where it can be
// forwarded, scanned by a mail security appliance, or prefetched by a
// client before the recipient ever sees it — so it should live for only as
// long as a legitimate recipient plausibly needs to click it, not as long
// as a password-reset link a human reads and then types a new password
// after. The previous behavior, before this option existed, was both
// flows sharing TokenDuration (default 1h); a deployment relying on that
// 1h magic-link window must now set WithMagicLinkDuration(time.Hour)
// explicitly.
func WithMagicLinkDuration(d time.Duration) Option {
	return func(c *Config) { c.MagicLinkDuration = d }
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

// WithPepper sets a secret pepper mixed into every password via
// HMAC-SHA256 before Argon2 (see password.go's applyPepper). It protects
// against a database-only leak — a copy of the user table with no access
// to application config or secrets yields hashes nobody can run an offline
// dictionary attack against without also having the pepper. It does NOT
// protect against a full application compromise: the same process that
// hashes passwords holds the pepper, so an attacker who reaches that
// process reaches both.
//
// Losing the pepper makes EVERY stored hash permanently unverifiable —
// there is no fallback, unlike a hash's own salt (which travels with the
// hash). Store it with the same care as a private key: outside version
// control, in a secrets manager or environment variable, never beside the
// database it is meant to protect.
//
// The pepper is a first-deployment decision, not a knob to turn later.
// Setting one where there was none, changing its value, or clearing one
// that was set makes every hash written under the old configuration
// unverifiable: verifyPassword applies whichever pepper is CURRENTLY
// configured, uniformly, to both the NFKC and pre-NFKC forms its existing
// T505 legacy-fallback seam already tries (see the T505 Decisions row) —
// it does not also try "with each pepper this deployment has ever used" on
// top of that. Unlike T505's normalization fallback, which is safe to widen
// because it can only ever match the exact bytes a hash was already
// derived from, a pepper-introduced-later problem is symmetric with a
// pepper-changed or pepper-removed one: there is no single "old form" to
// fall back to, only an unbounded list of past values this library has no
// way to know. Introduce a pepper before the first password is ever hashed,
// or plan on resetting affected users' passwords when introducing one
// later — the same recovery path already used for a lost password, not a
// new failure mode.
func WithPepper(pepper []byte) Option {
	return func(c *Config) { c.Pepper = append([]byte(nil), pepper...) }
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

// WithMagicLinkBinding controls whether redeeming a magic link requires a
// binding nonce matching the one CreateMagicLinkToken generated alongside
// the token (default: true).
//
// CreateMagicLinkToken returns (token, bindingNonce string, err error). The
// application is expected to set bindingNonce as a short-lived, HttpOnly
// cookie on the response to the request that triggered issuance — NOT to
// embed it in the emailed link itself, which would defeat the entire
// point — and to read it back from that cookie when the link is later
// clicked, passing it to RedeemMagicLink alongside the token recovered
// from the link's query string. Because the nonce travels only in a
// cookie scoped to the browser that requested the link, a copy of the
// link forwarded to, or opened by, a different device or browser arrives
// without the matching cookie: RedeemMagicLink then rejects it with
// ErrTokenInvalid even though the token itself is still valid, unused, and
// unexpired. That is what makes a forwarded magic link useless to whoever
// it was forwarded to.
//
// The nonce is stored hashed (SHA-256, alongside the token's own hash —
// see Token.NonceHash), never in plaintext, and compared at redemption via
// crypto/subtle.ConstantTimeCompare over the hashes, exactly as
// VerifyCSRFToken compares its own double-submit token.
//
// Passing false accepts any bindingNonce value at redemption — including
// "" — because CreateMagicLinkToken stops generating one at all: it
// returns bindingNonce == "" and the created Token carries no NonceHash
// for RedeemMagicLink to check against. The trade-off: without binding, a
// magic link works from whatever device or browser opens it, which is
// convenient when mail is routinely read somewhere other than where the
// link was requested (a common case — requesting from a desktop, opening
// from a phone's mail app) — but it also means a link forwarded to
// someone else, or consumed by an automated mail scanner that prefetches
// links before a human ever clicks, signs that other party or scanner in
// instead. Turning this off is a deliberate, greppable trade-off; make it
// with that risk in mind, not by leaving it at the default without
// thinking about it. See the README's magic-link section for the prefetch
// hazard and why a confirmation click (rather than a bare GET link) is
// recommended regardless of this setting.
func WithMagicLinkBinding(b bool) Option {
	return func(c *Config) { c.MagicLinkBinding = b }
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

// WithCookieName overrides the session cookie's name (default:
// "__Host-session"). New rejects a name that isn't a valid HTTP cookie
// token (empty, or containing whitespace/control/separator characters).
//
// Choosing a name without the "__Host-" prefix is a valid, explicit
// opt-out of that browser-enforced guarantee (see defaultCookieName) — do
// this only if you have a concrete reason to (for instance, sharing the
// cookie across subdomains via an explicit Domain your own reverse proxy
// adds, which this package's cookies never set themselves). Secure, Path=/,
// and HttpOnly are set on SessionCookie/ClearSessionCookie regardless of
// name: nothing in this package's configuration surface can turn them off.
func WithCookieName(name string) Option {
	return func(c *Config) { c.CookieName = name }
}

// WithTokenSource restricts which channel(s) Authenticate accepts a
// session token from (default: TokenSourceBoth). See TokenSource's own
// constants for what each value means and why TokenSourceBoth remains the
// default.
func WithTokenSource(ts TokenSource) Option {
	return func(c *Config) { c.TokenSource = ts }
}
