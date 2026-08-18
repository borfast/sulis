package sulis

import (
	"context"
	"time"
)

// CreateTwoFactorToken generates a short-lived, single-use pending-login
// token for a user who has passed the first authentication factor. Returns
// ErrEmailNotVerified if the account's email is unverified and
// RequireVerifiedEmail is enabled (default), failing before the app ever
// prompts for a second factor.
//
// Intended app flow: VerifyPassword -> (app checks its own "user has 2FA"
// flag) -> CreateTwoFactorToken -> (app verifies the second factor: TOTP,
// recovery code, or passkey) -> CompleteTwoFactor. No session exists until
// CompleteTwoFactor succeeds.
func (s *Sulis) CreateTwoFactorToken(ctx context.Context, userID string) (string, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if err := s.requireVerifiedEmail(user); err != nil {
		return "", err
	}
	return s.createTokenForUser(ctx, userID, TokenPurposeTwoFactor, s.cfg.TwoFactorTokenDuration)
}

// CompleteTwoFactor consumes a two-factor pending-login token issued by
// CreateTwoFactorToken and, once the app has independently verified the
// user's second factor, issues a new session. The token is single-use and
// purpose-scoped: it cannot be replayed, and it is rejected by any flow
// other than CompleteTwoFactor. Also returns ErrEmailNotVerified — as
// defense in depth, since the token is consumed either way — if the
// account's email is unverified and RequireVerifiedEmail is enabled
// (default); this checks the user's current state, not its state when the
// token was minted.
//
// userID must be the ID the app obtained from its own VerifyPassword call
// and carried through its own server-side state (e.g. keyed by the pending
// token) — never a value supplied by the client on the second-factor
// request. The token is consumed first and then checked against userID,
// rejecting with ErrTokenInvalid on a mismatch; either way the token is
// burned, so a mismatched userID cannot be retried against the same token.
func (s *Sulis) CompleteTwoFactor(ctx context.Context, userID, rawToken string, ri RequestInfo) (*LoginResult, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeTwoFactor)
	if err != nil {
		return nil, err
	}
	if token.UserID != userID {
		return nil, ErrTokenInvalid
	}
	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	// This mints a session directly, exactly like completeFirstFactor and
	// issueSessionForUser do (see accountStatus's doc comment on why every
	// such path checks this) — an account disabled between the first
	// factor and this completion step must not be able to finish logging
	// in on the strength of a pending token minted before the disable.
	if err := s.accountStatus(user); err != nil {
		return nil, err
	}
	if err := s.requireVerifiedEmail(user); err != nil {
		return nil, err
	}
	// Both factors are done, so this issues a session directly rather than
	// going through completeFirstFactor — asking the checker again here would
	// demand a second factor immediately after verifying one. It also skips
	// the public IssueSession(Authentication) path: user is already loaded,
	// and IssueSession would just reload it by ID, paying a store round trip
	// this call site doesn't need to pay. Everything this function just
	// checked (token ownership, current email-verification state) is exactly
	// what an Authentication would otherwise vouch for. The session records
	// AuthMethodTwoFactor, not whichever method passed the first factor:
	// the second factor is what actually authorized this session.
	session, sessionToken, err := s.createSession(ctx, user.ID, AuthMethodTwoFactor, time.Now())
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: user, Session: session, SessionToken: sessionToken}, nil
}
