package sulis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Sulis is the main authentication service. It coordinates user registration,
// login, password reset, and session management.
type Sulis struct {
	users     UserStore
	sessions  SessionStore
	tokens    TokenStore
	factors   SecondFactorChecker
	cfg       Config
	dummyHash string // used to equalize Login timing for unknown/passwordless users
}

// New creates a new Sulis instance with the given stores and options.
//
// factors is required and must not be nil: it is how the library learns that a
// user has a second factor, and defaulting it would mean silently issuing
// fully-privileged sessions to accounts that expect two-factor authentication.
// Applications with no second factors pass NoSecondFactors{}.
func New(users UserStore, sessions SessionStore, tokens TokenStore, factors SecondFactorChecker, opts ...Option) (*Sulis, error) {
	switch {
	case users == nil:
		return nil, fmt.Errorf("sulis: UserStore must not be nil")
	case sessions == nil:
		return nil, fmt.Errorf("sulis: SessionStore must not be nil")
	case tokens == nil:
		return nil, fmt.Errorf("sulis: TokenStore must not be nil")
	case factors == nil:
		return nil, fmt.Errorf("sulis: SecondFactorChecker must not be nil; pass sulis.NoSecondFactors{} if this application has no second factors")
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.MinPasswordLength > cfg.MaxPasswordLength {
		return nil, fmt.Errorf("sulis: minimum password length %d exceeds maximum %d", cfg.MinPasswordLength, cfg.MaxPasswordLength)
	}

	s := &Sulis{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		factors:  factors,
		cfg:      cfg,
	}
	// crypto/rand cannot fail on Go >= 1.24, so ignoring the error here is safe.
	s.dummyHash, _ = hashPassword("sulis-timing-equalization-dummy", cfg.Argon2)
	return s, nil
}

// Register creates a new user with the given email and password, and returns
// a new session. Returns ErrUserAlreadyExists if the email is already taken.
func (s *Sulis) Register(ctx context.Context, email, password string, ri RequestInfo) (*User, *Session, string, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, nil, "", err
	}

	if err := s.checkPasswordPolicy(password); err != nil {
		return nil, nil, "", err
	}

	hash, err := hashPassword(password, s.cfg.Argon2)
	if err != nil {
		return nil, nil, "", fmt.Errorf("sulis: hashing password: %w", err)
	}

	now := time.Now()
	user := &User{
		ID:           generateID(),
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.CreateUser(ctx, user); err != nil {
		return nil, nil, "", err
	}

	session, token, err := s.createSession(ctx, user.ID, AuthMethodPassword, now, ri)
	if err != nil {
		return nil, nil, "", err
	}

	return user, session, token, nil
}

// Login authenticates a user with email and password.
//
// A correct password is only the FIRST factor. If the configured
// SecondFactorChecker reports that the user has one enrolled, the returned
// LoginResult has NeedsSecondFactor set and carries a PendingToken instead of
// a session — no session exists until CompleteTwoFactor succeeds. Callers must
// branch on NeedsSecondFactor rather than assuming a non-nil result means the
// user is logged in.
//
// Returns ErrInvalidCredentials if the email or password is wrong, and
// ErrEmailNotVerified if the account is unverified and RequireVerifiedEmail is
// enabled (the default).
func (s *Sulis) Login(ctx context.Context, email, password string, ri RequestInfo) (*LoginResult, error) {
	user, err := s.VerifyPassword(ctx, email, password, ri)
	if err != nil {
		return nil, err
	}
	return s.completeFirstFactor(ctx, user, AuthMethodPassword, ri)
}

// VerifyPassword checks an email and password against the stored credentials
// without creating a session. Returns ErrInvalidCredentials if the email or
// password is wrong. Like Login, it equalizes response timing for
// unknown-user and passwordless-user cases by running the same Argon2 work
// against a dummy hash.
func (s *Sulis) VerifyPassword(ctx context.Context, email, password string, ri RequestInfo) (*User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}

	if err := s.allow(ctx, "password:"+email); err != nil {
		return nil, err
	}
	if err := s.allowIP(ctx, "password:", ri); err != nil {
		return nil, err
	}

	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Run the same Argon2 work a real verification would, so the
			// response time doesn't reveal whether the account exists.
			_, _ = verifyPassword(password, s.dummyHash)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.PasswordHash == "" {
		// Passwordless user: verify against the dummy hash for the same reason.
		_, _ = verifyPassword(password, s.dummyHash)
		return nil, ErrInvalidCredentials
	}

	ok, err := verifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("sulis: verifying password: %w", err)
	}
	if !ok {
		if s.cfg.FailureLockoutThreshold > 0 {
			s.recordFailedLogin(ctx, user.ID)
		}
		return nil, ErrInvalidCredentials
	}

	// The password just verified against a hash weaker than the currently
	// configured Argon2Params (e.g. an operator raised the cost since this
	// user last logged in) — upgrade the stored hash now, while the
	// plaintext is still in hand. Only a successful verification reaches
	// this point, so a failed or unknown-user/passwordless login never
	// rehashes anything, and this runs after the ok check above rather than
	// changing its timing.
	if needsRehash(user.PasswordHash, s.cfg.Argon2) {
		s.rehashPassword(ctx, user, password)
	}

	// The password just verified, so from here on the caller has proven
	// they know it — only now is it safe to reveal disabled/locked status.
	// Checking this any earlier (e.g. before the password comparison, or on
	// the unknown-user/passwordless branches above) would let an
	// unauthenticated caller learn that an account exists and is disabled
	// or locked purely from the shape of the error, without ever guessing
	// the password. See accountStatus's doc comment.
	if err := s.accountStatus(user); err != nil {
		return nil, err
	}

	if s.cfg.FailureLockoutThreshold > 0 && (user.FailedLoginAttempts != 0 || user.LockedUntil != nil) {
		// The lockout window (if any) has already passed — accountStatus
		// would have returned ErrAccountLocked above otherwise — and the
		// correct password just proved ownership, so clear the stale
		// bookkeeping rather than leaving it to linger.
		s.clearFailedLogins(ctx, user.ID)
	}

	return user, nil
}

// rehashPassword upgrades user's stored hash to the currently configured
// Argon2 parameters, now that password has just been verified against the
// hash it is about to replace. Called only from VerifyPassword's
// successful-verification path, after needsRehash reports the stored hash
// is weaker than s.cfg.Argon2.
//
// The write goes through updateUserWithRetry with a guard — re-checked
// against the freshly loaded row on every attempt — that only applies the
// upgrade while u.PasswordHash still equals the hash that was just
// verified: the same discipline ChangePassword's verifyOld guard uses. A
// password changed by another request between VerifyPassword's read and
// this write must not be silently overwritten with a rehash of the
// password it just replaced.
//
// Any failure — the guard losing the race, a store error, or hashPassword
// itself failing — is deliberately swallowed. The caller already
// authenticated correctly by the time this runs; only the cost of the next
// verification is at stake, not correctness, so a failed upgrade here must
// never fail the login. The next successful login against a still-weak
// hash simply tries again.
func (s *Sulis) rehashPassword(ctx context.Context, user *User, password string) {
	verifiedHash := user.PasswordHash

	newHash, err := hashPassword(password, s.cfg.Argon2)
	if err != nil {
		// TODO(T509): emit rehash event
		return
	}

	now := time.Now()
	_, err = s.updateUserWithRetry(ctx, user.ID, func(u *User) error {
		if u.PasswordHash != verifiedHash {
			return errRehashPasswordChanged
		}
		u.PasswordHash = newHash
		u.UpdatedAt = now
		return nil
	})
	if err != nil {
		// Best-effort: see the doc comment above. errRehashPasswordChanged,
		// ErrConcurrentUpdate exhausting its retries, and any store error
		// all land here and are all equally fine to drop.
		// TODO(T509): emit rehash event
		return
	}
	// TODO(T509): emit rehash event
}

// errRehashPasswordChanged aborts rehashPassword's update when a concurrent
// request has changed the password since it was verified. It never
// escapes rehashPassword, which swallows every failure — the return type
// exists only to make the abort explicit at the point it happens, rather
// than smuggling a sentinel string through fmt.Errorf.
var errRehashPasswordChanged = errors.New("sulis: password changed during rehash")

// ChangePassword changes a user's password after verifying the old password.
// The length policy applies only to the new password; the old one was
// already validated when it was set.
func (s *Sulis) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string, ri RequestInfo) error {
	if err := s.checkPasswordPolicy(newPassword); err != nil {
		return err
	}

	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.allow(ctx, "password:"+user.Email); err != nil {
		return err
	}
	if err := s.allowIP(ctx, "password:", ri); err != nil {
		return err
	}

	// Checked inside the update, so it re-runs against current state on a
	// retry: a password changed by another request between this read and the
	// write must not be replaced on the strength of a stale check.
	verifyOld := func(u *User) error {
		if u.PasswordHash == "" {
			return ErrInvalidCredentials
		}
		ok, err := verifyPassword(oldPassword, u.PasswordHash)
		if err != nil {
			return fmt.Errorf("sulis: verifying old password: %w", err)
		}
		if !ok {
			return ErrInvalidCredentials
		}
		return nil
	}

	return s.setPassword(ctx, user.ID, newPassword, verifyOld)
}

// SetInitialPassword sets the first password for a passwordless user.
func (s *Sulis) SetInitialPassword(ctx context.Context, userID, newPassword string) error {
	if err := s.checkPasswordPolicy(newPassword); err != nil {
		return err
	}

	// The passwordless check runs inside the update so two concurrent
	// bootstrap attempts cannot both succeed.
	return s.setPassword(ctx, userID, newPassword, func(u *User) error {
		if u.PasswordHash != "" {
			return ErrInvalidCredentials
		}
		return nil
	})
}

// checkPasswordPolicy enforces the configured minimum and maximum password
// length. Lengths are measured in bytes.
func (s *Sulis) checkPasswordPolicy(password string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > s.cfg.MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}

// maxUserUpdateAttempts bounds updateUserWithRetry. Conflicts are rare and
// resolve on the first retry in practice; the bound stops a pathological
// writer from spinning.
const maxUserUpdateAttempts = 3

// updateUserWithRetry loads the user, applies mutate, and persists the result,
// retrying from a fresh read if another writer won the race. mutate runs again
// on every attempt, so any invariant it checks is re-established against
// current state rather than the state the caller first read. A non-nil error
// from mutate aborts immediately and is returned unchanged.
func (s *Sulis) updateUserWithRetry(ctx context.Context, userID string, mutate func(*User) error) (*User, error) {
	var lastErr error
	for range maxUserUpdateAttempts {
		user, err := s.users.GetUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		if err := mutate(user); err != nil {
			return nil, err
		}
		if err := s.users.UpdateUser(ctx, user); err != nil {
			if !errors.Is(err, ErrConcurrentUpdate) {
				return nil, err
			}
			lastErr = err
			continue
		}
		return user, nil
	}
	return nil, lastErr
}

// setPassword writes a new password hash for userID. guard, if non-nil, is
// re-checked against the freshly loaded user on every attempt, so a concurrent
// change cannot slip past a check the caller made before calling.
//
// It also clears any active automatic lockout (FailedLoginAttempts,
// LockedUntil) — proving control of the account well enough to set a new
// password (ChangePassword's old password, ResetPassword's out-of-band
// token, or SetInitialPassword's caller-vouched-for trusted flow) is at
// least as strong an identity proof as the correct login password
// VerifyPassword's own success path already treats as grounds for clearing
// it. Without this, an attacker could lock a victim out via repeated wrong
// guesses and the victim's own password reset would not restore access
// until the lockout's backoff passed — worsening the exact denial-of-service
// risk WithFailureLockout's default-off posture exists to limit, and made
// worse still by the recommendation (see WithFailureLockout's doc comment)
// to configure a long maxBackoff. DisabledAt/DisabledReason are deliberately
// NOT cleared here: disabling is an operator action, reversed only by
// EnableUser, not by proving control of the password.
func (s *Sulis) setPassword(ctx context.Context, userID, newPassword string, guard func(*User) error) error {
	// Hashed once, outside the retry loop: a conflict should not make the
	// caller pay for Argon2 again.
	hash, err := hashPassword(newPassword, s.cfg.Argon2)
	if err != nil {
		return fmt.Errorf("sulis: hashing new password: %w", err)
	}

	now := time.Now()
	user, err := s.updateUserWithRetry(ctx, userID, func(u *User) error {
		if guard != nil {
			if err := guard(u); err != nil {
				return err
			}
		}
		u.PasswordHash = hash
		u.UpdatedAt = now
		u.FailedLoginAttempts = 0
		u.LockedUntil = nil
		return nil
	})
	if err != nil {
		return err
	}

	if s.cfg.RevokeSessionsOnPasswordChange {
		if err := s.sessions.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
	}
	if err := s.tokens.DeleteUserTokens(ctx, user.ID, TokenPurposePasswordReset); err != nil {
		return err
	}
	// A pending 2FA login token was minted against the old password's first
	// factor; once the password changes, that pending login must not be
	// completable, so purge it too.
	return s.tokens.DeleteUserTokens(ctx, user.ID, TokenPurposeTwoFactor)
}

// resetTokenGenerator produces the raw/hashed token pair burned on the
// unknown-user path of CreatePasswordResetToken. It is a package variable —
// rather than a direct call to generateRawToken — purely so tests can prove
// that generation work actually happens on that path (via a counting
// wrapper), without needing a real user or a token-store write to observe
// it. Production code never reassigns it.
var resetTokenGenerator = generateRawToken

// CreatePasswordResetToken generates a password reset token for the given
// email and returns the raw token so the consumer can deliver it (e.g. via
// email).
//
// If no account exists for email, it returns ("", nil) rather than
// ErrUserNotFound: this endpoint must not let a caller learn whether an
// address is registered. The unknown-user path still generates and hashes a
// token of the same size the known-user path would create — burning the
// same randomness and hashing work — before discarding it, so the two paths
// can't be told apart by the work they perform either. What can't be
// equalized is the store round trip: the known-user path writes a token row
// and the unknown-user path never does, since there is no user to attach one
// to. That residual asymmetry is the same kind VerifyPassword documents for
// its dummy-hash equalization above — perfect timing equality across a
// storage boundary isn't a claim this library can make.
//
// Admin tooling that has already authenticated an operator and genuinely
// needs to know whether the address is registered should call
// CreatePasswordResetTokenStrict instead; it must never back a public-facing
// endpoint, or it reopens the user-enumeration oracle this method closes.
func (s *Sulis) CreatePasswordResetToken(ctx context.Context, email string, ri RequestInfo) (string, error) {
	return s.createPasswordResetToken(ctx, email, ri, false)
}

// CreatePasswordResetTokenStrict behaves exactly like CreatePasswordResetToken
// except that it returns ErrUserNotFound verbatim for an unknown address
// instead of silently returning ("", nil). It exists for admin tooling that
// needs the truth about whether an address is registered; wiring it to a
// public-facing endpoint reintroduces the enumeration oracle
// CreatePasswordResetToken exists to close.
func (s *Sulis) CreatePasswordResetTokenStrict(ctx context.Context, email string, ri RequestInfo) (string, error) {
	return s.createPasswordResetToken(ctx, email, ri, true)
}

// createPasswordResetToken implements both CreatePasswordResetToken and
// CreatePasswordResetTokenStrict; strict selects which of them the caller is.
func (s *Sulis) createPasswordResetToken(ctx context.Context, email string, ri RequestInfo, strict bool) (string, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return "", err
	}

	if err := s.allow(ctx, "reset:"+email); err != nil {
		return "", err
	}
	if err := s.allowIP(ctx, "reset:", ri); err != nil {
		return "", err
	}

	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			if strict {
				return "", err
			}
			// Burn the same generation and hashing work a real issuance
			// would spend, then discard the result: there is no user row to
			// attach a stored token to, and persisting one anyway would
			// leave an orphaned, unredeemable row behind. crypto/rand cannot
			// fail on Go >= 1.24 (see New), so the error is safe to ignore
			// here too.
			_, _, _ = resetTokenGenerator(s.cfg.ResetTokenBytes)
			return "", nil
		}
		return "", err
	}

	return s.createTokenForUser(ctx, user.ID, TokenPurposePasswordReset, s.cfg.TokenDuration)
}

// ResetPassword resets a user's password using a raw reset token. The
// password policy is checked before the token is consumed, so a policy
// failure does not burn the token.
func (s *Sulis) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if err := s.checkPasswordPolicy(newPassword); err != nil {
		return err
	}

	token, err := s.consumeToken(ctx, rawToken, TokenPurposePasswordReset)
	if err != nil {
		return err
	}

	return s.setPassword(ctx, token.UserID, newPassword, nil)
}

// ValidateSession validates a session token and returns the session and user.
// Returns ErrSessionNotFound or ErrSessionExpired on failure.
//
// A session past its idle deadline (IdleExpiresAt, set only when
// WithIdleTimeout is configured) is rejected the same way as one past its
// absolute ExpiresAt — checked first, since idle expiry exists to end a
// session well before its absolute lifetime in the common case, and either
// way the outcome (ErrSessionExpired, the row deleted) is identical.
//
// On success, LastSeenAt/IdleExpiresAt are refreshed via TouchSession, but
// only when the session's current LastSeenAt is already older than
// sessionTouchInterval — see that constant's doc comment (session.go) for
// why this is throttled rather than written on every call. The touch is
// best effort: a failed write does not fail validation, since the session
// itself is still valid regardless of whether its liveness bookkeeping
// happens to update this time.
func (s *Sulis) ValidateSession(ctx context.Context, token string) (*Session, *User, error) {
	tokenHash := hashSessionToken(token)
	session, err := s.sessions.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, err
	}
	validated := *session

	now := time.Now()
	if validated.IdleExpiresAt != nil && now.After(*validated.IdleExpiresAt) {
		_ = s.sessions.DeleteSession(ctx, validated.UserID, validated.ID)
		return nil, nil, ErrSessionExpired
	}
	if now.After(validated.ExpiresAt) {
		_ = s.sessions.DeleteSession(ctx, validated.UserID, validated.ID)
		return nil, nil, ErrSessionExpired
	}

	user, err := s.users.GetUserByID(ctx, validated.UserID)
	if err != nil {
		return nil, nil, err
	}

	// Checked here, not just at issuance: this is what makes DisableUser
	// take effect on every session already outstanding, not merely on the
	// next login. Without it, disabling would leave live sessions working
	// for the rest of their natural lifetime. Deliberately only DisabledAt,
	// not LockedUntil — an automatic lockout (see WithFailureLockout)
	// throttles new authentication attempts; it does not invalidate a
	// session already issued before the lockout began.
	if user.DisabledAt != nil {
		return nil, nil, ErrAccountDisabled
	}

	if now.Sub(validated.LastSeenAt) >= s.sessionTouchInterval() {
		idleExpiresAt := s.idleExpiresAt(now)
		if err := s.sessions.TouchSession(ctx, validated.ID, now, idleExpiresAt); err == nil {
			validated.LastSeenAt = now
			validated.IdleExpiresAt = idleExpiresAt
		}
	}

	return &validated, user, nil
}

// RevokeSession deletes a single session belonging to userID. It returns
// ErrSessionNotFound if sessionID does not exist or belongs to a different
// user, so a caller can only ever revoke their own sessions — guessing or
// leaking another user's session ID cannot be used to end their session.
func (s *Sulis) RevokeSession(ctx context.Context, userID, sessionID string) error {
	return s.sessions.DeleteSession(ctx, userID, sessionID)
}

// RevokeAllSessions deletes all sessions for a user.
func (s *Sulis) RevokeAllSessions(ctx context.Context, userID string) error {
	return s.sessions.DeleteUserSessions(ctx, userID)
}

// createTokenForUser generates a token for the given user, purpose, and TTL.
// The token is not bound to a specific email address; use
// createTokenForUserWithEmail for tokens (like email verification) that must
// be invalidated if the user's address changes after issuance.
func (s *Sulis) createTokenForUser(ctx context.Context, userID string, purpose TokenPurpose, ttl time.Duration) (string, error) {
	return s.createTokenForUserWithEmail(ctx, userID, "", purpose, ttl)
}

// createTokenForUserWithEmail generates a token for the given user and
// purpose, recording email as the address the token proves control of. Pass
// an empty email for tokens that aren't bound to a specific address.
func (s *Sulis) createTokenForUserWithEmail(ctx context.Context, userID, email string, purpose TokenPurpose, ttl time.Duration) (string, error) {
	raw, hashed, err := generateRawToken(s.cfg.ResetTokenBytes)
	if err != nil {
		return "", fmt.Errorf("sulis: generating token: %w", err)
	}

	now := time.Now()
	token := &Token{
		ID:        generateID(),
		UserID:    userID,
		Email:     email,
		TokenHash: hashed,
		Purpose:   purpose,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	if err := s.tokens.CreateToken(ctx, token); err != nil {
		return "", err
	}

	return raw, nil
}

// consumeToken atomically consumes a raw token for the given purpose. Expiry
// is checked after consumption so failures burn the token (safe direction).
func (s *Sulis) consumeToken(ctx context.Context, rawToken string, purpose TokenPurpose) (*Token, error) {
	token, err := s.tokens.ConsumeToken(ctx, hashToken(rawToken), purpose)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrTokenInvalid
		}
		return nil, err // ErrTokenAlreadyUsed and store failures propagate
	}
	if time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	return token, nil
}

// allow consults the configured rate limiter for key, if one is set. A nil
// limiter is a no-op. Any error from the limiter is normalized to
// ErrRateLimited so callers never leak limiter implementation details.
func (s *Sulis) allow(ctx context.Context, key string) error {
	if s.cfg.Limiter == nil {
		return nil
	}
	if err := s.cfg.Limiter.Allow(ctx, key); err != nil {
		return ErrRateLimited
	}
	return nil
}

// requireVerifiedEmail returns ErrEmailNotVerified if RequireVerifiedEmail is
// enabled and user's email has not been verified. A nil result means the
// caller may proceed with issuing a session or minting a two-factor token.
func (s *Sulis) requireVerifiedEmail(user *User) error {
	if s.cfg.RequireVerifiedEmail && user.EmailVerifiedAt == nil {
		return ErrEmailNotVerified
	}
	return nil
}

// generateID creates a random hex-encoded ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeEmail trims surrounding whitespace, validates the result as a
// single RFC 5322 address (rejecting display-name forms like "Name <a@b>"),
// and lowercases it for consistent storage and comparison. Returns
// ErrInvalidEmail for empty, overlong (>254 bytes), or malformed input.
func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 254 {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email { // rejects "Name <a@b>" forms
		return "", ErrInvalidEmail
	}
	return strings.ToLower(email), nil
}
