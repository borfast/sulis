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

	session, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: user, Session: session, SessionToken: session.Token}, nil
}

// createSession creates a new session for the given user.
func (s *Sulis) createSession(ctx context.Context, userID string) (*Session, error) {
	token, err := generateSessionToken(s.cfg.SessionTokenBytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        generateID(),
		UserID:    userID,
		Token:     token,
		TokenHash: hashSessionToken(token),
		ExpiresAt: now.Add(s.cfg.SessionDuration),
		CreatedAt: now,
	}

	persisted := *session
	persisted.Token = ""

	if err := s.sessions.CreateSession(ctx, &persisted); err != nil {
		return nil, err
	}

	return session, nil
}
