package sulis

import (
	"context"
	"errors"
	"time"
)

// errAlreadyVerified aborts the stampEmailVerified update when another writer
// verified the address first. It never escapes this package.
var errAlreadyVerified = errors.New("sulis: email already verified")

// CreateEmailVerificationToken generates a short-lived, single-use token
// proving control of the given user's registered email address. The token
// is bound to the user's current (normalized) email at issuance time, so it
// is invalidated by VerifyEmail if the address changes before redemption.
// The raw token is returned so the consumer can deliver it (e.g. via email).
func (s *Sulis) CreateEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	return s.createTokenForUserWithEmail(ctx, user.ID, user.Email, TokenPurposeEmailVerification, s.cfg.EmailVerificationTokenDuration)
}

// VerifyEmail consumes an email-verification token issued by
// CreateEmailVerificationToken and stamps the user's EmailVerifiedAt. The
// token is single-use and purpose-scoped: it cannot be replayed, and it is
// rejected by any flow other than VerifyEmail. It is also rejected with
// ErrTokenInvalid if the user's email has changed since the token was
// issued, so a verification token can never prove control of an address the
// user no longer holds.
func (s *Sulis) VerifyEmail(ctx context.Context, rawToken string) (*User, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeEmailVerification)
	if err != nil {
		return nil, err
	}
	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	if token.Email != user.Email {
		return nil, ErrTokenInvalid
	}
	return user, s.stampEmailVerified(ctx, user)
}

// stampEmailVerified marks the user's email as verified. It is idempotent:
// once EmailVerifiedAt is set, subsequent calls are no-ops so a later
// verification path (e.g. a second magic link redemption) does not bump the
// original timestamp.
//
// If this is the first verification for an account that already has a
// password, all of the user's sessions are revoked unconditionally (not
// gated by RevokeSessionsOnPasswordChange): an attacker may have registered
// the victim's email with their own password before the victim ever proved
// mailbox control, and any session that attacker is holding must not
// survive the victim's first successful verification. Applications should
// additionally force a password reset on this path, since the attacker's
// chosen password otherwise remains valid.
func (s *Sulis) stampEmailVerified(ctx context.Context, user *User) error {
	if user.EmailVerifiedAt != nil {
		return nil
	}

	var hadPassword bool
	now := time.Now()
	updated, err := s.updateUserWithRetry(ctx, user.ID, func(u *User) error {
		if u.EmailVerifiedAt != nil {
			return errAlreadyVerified
		}
		// Read from the freshly loaded row, not the caller's copy: a password
		// set between the caller's read and this write still counts.
		hadPassword = u.PasswordHash != ""
		u.EmailVerifiedAt = &now
		u.UpdatedAt = now
		return nil
	})
	if err != nil {
		if errors.Is(err, errAlreadyVerified) {
			return nil
		}
		return err
	}
	// Give the caller the row as persisted, so the *User it returns reflects
	// the verification and carries the current version.
	*user = *updated

	if hadPassword {
		if err := s.sessions.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
	}
	return nil
}
