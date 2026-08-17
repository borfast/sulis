package sulis

import "context"

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
	if err := s.requireVerifiedEmail(user); err != nil {
		return nil, err
	}
	// Both factors are done, so this issues a session directly rather than
	// going through completeFirstFactor — asking the checker again here would
	// demand a second factor immediately after verifying one.
	session, sessionToken, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: user, Session: session, SessionToken: sessionToken}, nil
}
