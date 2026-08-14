package sulis

import "context"

// CreateTwoFactorToken generates a short-lived, single-use pending-login
// token for a user who has passed the first authentication factor.
//
// Intended app flow: VerifyPassword -> (app checks its own "user has 2FA"
// flag) -> CreateTwoFactorToken -> (app verifies the second factor: TOTP,
// recovery code, or passkey) -> CompleteTwoFactor. No session exists until
// CompleteTwoFactor succeeds.
func (s *Sulis) CreateTwoFactorToken(ctx context.Context, userID string) (string, error) {
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return "", err
	}
	return s.createTokenForUser(ctx, userID, TokenPurposeTwoFactor, s.cfg.TwoFactorTokenDuration)
}

// CompleteTwoFactor consumes a two-factor pending-login token issued by
// CreateTwoFactorToken and, once the app has independently verified the
// user's second factor, issues a new session. The token is single-use and
// purpose-scoped: it cannot be replayed, and it is rejected by any flow
// other than CompleteTwoFactor.
//
// userID must be the ID the app obtained from its own VerifyPassword call
// and carried through its own server-side state (e.g. keyed by the pending
// token) — never a value supplied by the client on the second-factor
// request. The token is consumed first and then checked against userID,
// rejecting with ErrTokenInvalid on a mismatch; either way the token is
// burned, so a mismatched userID cannot be retried against the same token.
func (s *Sulis) CompleteTwoFactor(ctx context.Context, userID, rawToken string) (*User, *Session, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeTwoFactor)
	if err != nil {
		return nil, nil, err
	}
	if token.UserID != userID {
		return nil, nil, ErrTokenInvalid
	}
	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, err
	}
	session, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	return user, session, nil
}
