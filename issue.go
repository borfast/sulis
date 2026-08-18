package sulis

import (
	"context"
	"fmt"
	"time"
)

// AuthMethod names the credential that authenticated a session.
type AuthMethod string

const (
	AuthMethodPassword     AuthMethod = "password"
	AuthMethodMagicLink    AuthMethod = "magic_link"
	AuthMethodPasskey      AuthMethod = "passkey"
	AuthMethodTwoFactor    AuthMethod = "two_factor"
	AuthMethodRecoveryCode AuthMethod = "recovery_code"
)

// RequestInfo carries per-request caller context. It feeds the IP dimension of
// rate limiting and is recorded on sessions so users can recognise their own
// devices. The zero value is valid: callers with nothing to report pass
// RequestInfo{}.
type RequestInfo struct {
	IP        string
	UserAgent string
}

// SecondFactorChecker reports whether a user has an enrolled second factor.
//
// It is a required argument to New rather than an option, because a default
// would silently answer "no" — and answering "no" by default is exactly the
// bypass this type exists to close. Applications that genuinely have no second
// factors pass NoSecondFactors{}, which says so in code rather than by omission.
//
// Implementations should consult whatever the application treats as a second
// factor: a verified TOTP enrollment, a registered passkey, or both.
type SecondFactorChecker interface {
	HasSecondFactor(ctx context.Context, userID string) (bool, error)
}

// NoSecondFactors is an explicit declaration that an application has no second
// factors at all. Prefer it over a hand-written stub, so the intent is greppable.
type NoSecondFactors struct{}

// HasSecondFactor always reports false.
func (NoSecondFactors) HasSecondFactor(context.Context, string) (bool, error) {
	return false, nil
}

// LoginResult is the outcome of a successful first factor.
//
// Exactly one outcome is populated. When NeedsSecondFactor is true, Session and
// SessionToken are empty and PendingToken holds a short-lived, single-use token
// to pass to CompleteTwoFactor once the application has verified the second
// factor. Otherwise Session and SessionToken hold a live session and its raw
// token, and PendingToken is empty.
//
// Callers must branch on NeedsSecondFactor. Treating a non-nil LoginResult as
// "logged in" defeats two-factor authentication.
type LoginResult struct {
	User              *User
	Session           *Session
	SessionToken      string
	NeedsSecondFactor bool
	PendingToken      string
}

// completeFirstFactor decides what a verified first factor earns. A user with
// an enrolled second factor gets a pending token and no session; everyone else
// gets a session.
//
// Every flow that authenticates a user by a single credential — password,
// magic link — must go through here. Calling createSession directly bypasses
// two-factor authentication.
func (s *Sulis) completeFirstFactor(ctx context.Context, user *User, method AuthMethod) (*LoginResult, error) {
	// This is the choke point Login (via VerifyPassword) and RedeemMagicLink
	// both pass through. VerifyPassword already checked account status, but
	// the magic-link path never calls VerifyPassword at all, so this is the
	// only check protecting it. Checked ahead of email verification: a
	// disabled or locked account should not surface a more specific
	// "unverified email" error.
	if err := s.accountStatus(user); err != nil {
		return nil, err
	}
	if err := s.requireVerifiedEmail(user); err != nil {
		return nil, err
	}

	hasSecond, err := s.factors.HasSecondFactor(ctx, user.ID)
	if err != nil {
		// Fail closed. An unavailable checker must never quietly downgrade an
		// account to a single factor.
		return nil, fmt.Errorf("sulis: checking second factor: %w", err)
	}

	if hasSecond {
		pending, err := s.createTokenForUser(ctx, user.ID, TokenPurposeTwoFactor, s.cfg.TwoFactorTokenDuration)
		if err != nil {
			return nil, err
		}
		return &LoginResult{User: user, NeedsSecondFactor: true, PendingToken: pending}, nil
	}

	session, token, err := s.createSession(ctx, user.ID, method, time.Now())
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: user, Session: session, SessionToken: token}, nil
}

// Authentication is opaque proof that a user has completed authentication —
// every factor sulis itself verified, not merely a caller's say-so. Its
// fields are unexported and there is no exported constructor that takes a
// bare user ID, so nothing outside this package can produce a valid value.
//
// The zero value carries no user ID. IssueSession rejects it (and any other
// invalid Authentication) with ErrNotAuthenticated rather than treating an
// empty user ID as real, so a forgotten or zeroed proof fails loudly instead
// of silently minting a session for whichever account that empty string
// happens to resolve to.
//
// completeFirstFactor mints one internally when a first factor is verified
// and no second factor is enrolled; CompleteTwoFactor mints one once the
// second factor is verified too. Neither currently routes through
// IssueSession itself — both already hold the *User in hand and call
// createSession/issueSessionForUser directly, avoiding the redundant store
// round trip IssueSession's user-ID-only input would otherwise force — but
// the type exists so that, in code rather than only in a doc comment, "this
// user is authenticated" is a value only this package can produce.
type Authentication struct {
	userID string
	method AuthMethod
	// at is when the factor behind this proof was verified. T305 minted it
	// but left it unread; T501 is its consumer: issueSessionForUser carries
	// it through to the minted Session's AuthenticatedAt, so a session
	// issued from a checked Authentication is stamped with the moment the
	// factor was actually proven rather than the moment (a store round trip
	// later) the session row happens to be written.
	at time.Time
}

// newAuthentication mints an Authentication proof for userID via method,
// timestamped now. It is unexported: this is the only way to produce a valid
// Authentication, and nothing outside this package can reach it.
func newAuthentication(userID string, method AuthMethod) Authentication {
	return Authentication{userID: userID, method: method, at: time.Now()}
}

// IssueSession creates a new session for the user identified by auth, which
// must come from completing a factor sulis itself verified. The zero value
// Authentication{} — and, since no exported constructor takes a bare user
// ID, any other Authentication not obtained from such a flow — is rejected
// with ErrNotAuthenticated before any store is touched.
//
// Beyond that check, this behaves exactly like IssueSessionUnchecked:
// ErrUserNotFound if the proof's user no longer exists, and
// ErrEmailNotVerified if the account's email is unverified and
// RequireVerifiedEmail is enabled (default).
//
// Applications authenticating by a factor sulis does not know how to verify
// itself — most notably a finished passkey ceremony, verified entirely by
// the passkey subpackage and the calling application — have no way to
// obtain an Authentication and must call IssueSessionUnchecked instead.
func (s *Sulis) IssueSession(ctx context.Context, auth Authentication) (*Session, string, error) {
	if auth.userID == "" {
		return nil, "", ErrNotAuthenticated
	}
	return s.issueSession(ctx, auth)
}

// IssueSessionUnchecked creates a new session for userID without requiring
// an Authentication proof. It is IssueSession's old, unguarded behavior kept
// under a name that says so in code review: legitimate for a factor sulis
// does not know about — most commonly a finished passkey ceremony, which
// has no way to produce an Authentication — but calling it means the
// CALLER, not this package, is vouching that userID has completed every
// factor the application requires. sulis performs no credential check of
// its own here, only the same ErrUserNotFound / ErrEmailNotVerified gating
// IssueSession applies. method records which credential the caller is
// vouching for; sulis does not yet act on it beyond that, but capturing it
// keeps this method's contract symmetric with IssueSession's.
func (s *Sulis) IssueSessionUnchecked(ctx context.Context, userID string, method AuthMethod) (*Session, string, error) {
	return s.issueSession(ctx, newAuthentication(userID, method))
}

// issueSession is the shared implementation behind IssueSession and
// IssueSessionUnchecked: load the user named by auth and hand off to
// issueSessionForUser.
func (s *Sulis) issueSession(ctx context.Context, auth Authentication) (*Session, string, error) {
	user, err := s.users.GetUserByID(ctx, auth.userID)
	if err != nil {
		return nil, "", err
	}
	return s.issueSessionForUser(ctx, user, auth.method, auth.at)
}

// issueSessionForUser gates and creates a session for an already-loaded user,
// avoiding a redundant store round-trip for callers (like Login) that already
// have the user in hand. method and authenticatedAt are stamped on the
// minted Session; issueSession passes auth.method and auth.at through
// unchanged, so the session's AuthenticatedAt reflects the moment the proof
// was actually minted rather than this call's own, slightly later, clock read.
func (s *Sulis) issueSessionForUser(ctx context.Context, user *User, method AuthMethod, authenticatedAt time.Time) (*Session, string, error) {
	// Gates IssueSession and IssueSessionUnchecked too: a caller vouching
	// for a factor sulis doesn't verify itself (e.g. a finished passkey
	// ceremony) must not be able to sidestep account status that way.
	if err := s.accountStatus(user); err != nil {
		return nil, "", err
	}
	if err := s.requireVerifiedEmail(user); err != nil {
		return nil, "", err
	}
	return s.createSession(ctx, user.ID, method, authenticatedAt)
}

// createSession creates a new session and returns it alongside the raw session
// token. The token is a return value rather than a field on Session, so the
// struct handed to SessionStore has no way to carry it. method and
// authenticatedAt are stamped on the session as Method and AuthenticatedAt;
// callers that authenticate and create the session in the same breath (e.g.
// completeFirstFactor, CompleteTwoFactor) pass time.Now(), while the
// Authentication-carrying path passes the proof's own timestamp instead — see
// issueSessionForUser.
func (s *Sulis) createSession(ctx context.Context, userID string, method AuthMethod, authenticatedAt time.Time) (*Session, string, error) {
	token, err := generateSessionToken(s.cfg.SessionTokenBytes)
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	session := &Session{
		ID:              generateID(),
		UserID:          userID,
		TokenHash:       hashSessionToken(token),
		ExpiresAt:       now.Add(s.cfg.SessionDuration),
		CreatedAt:       now,
		AuthenticatedAt: authenticatedAt,
		Method:          method,
	}

	if err := s.sessions.CreateSession(ctx, session); err != nil {
		return nil, "", err
	}

	return session, token, nil
}
