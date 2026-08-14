package sulis

import (
	"context"
	"time"
)

// CreateEmailVerificationToken generates a short-lived, single-use token
// proving control of the given user's registered email address. The raw
// token is returned so the consumer can deliver it (e.g. via email).
func (s *Sulis) CreateEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return "", err
	}
	return s.createTokenForUser(ctx, userID, TokenPurposeEmailVerification, s.cfg.EmailVerificationTokenDuration)
}

// VerifyEmail consumes an email-verification token issued by
// CreateEmailVerificationToken and stamps the user's EmailVerifiedAt. The
// token is single-use and purpose-scoped: it cannot be replayed, and it is
// rejected by any flow other than VerifyEmail.
func (s *Sulis) VerifyEmail(ctx context.Context, rawToken string) (*User, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeEmailVerification)
	if err != nil {
		return nil, err
	}
	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	return user, s.stampEmailVerified(ctx, user)
}

// stampEmailVerified marks the user's email as verified. It is idempotent:
// once EmailVerifiedAt is set, subsequent calls are no-ops so a later
// verification path (e.g. a second magic link redemption) does not bump the
// original timestamp.
func (s *Sulis) stampEmailVerified(ctx context.Context, user *User) error {
	if user.EmailVerifiedAt != nil {
		return nil
	}
	now := time.Now()
	user.EmailVerifiedAt = &now
	user.UpdatedAt = now
	return s.users.UpdateUser(ctx, user)
}
