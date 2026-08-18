package sulis

import (
	"context"
	"errors"
	"time"
)

// ChangeEmail stages newEmail as the account's pending address and returns a
// raw, single-use token proving intent to claim it. The live Email and
// EmailVerifiedAt are untouched: they change only when the returned token is
// later redeemed via ConfirmEmailChange. Staging a second address before the
// first is confirmed supersedes it — the earlier token is invalidated (see
// ConfirmEmailChange).
//
// Returns ErrInvalidEmail for a malformed address, and ErrUserAlreadyExists
// if newEmail is already the live address of any account, including this
// one — there is nothing to prove and nothing to change in that case.
//
// The raw token is returned once for the caller to deliver to the NEW
// address; sulis does not send mail. Callers MUST also notify the OLD
// address that a change has been requested — that notification, sent to an
// address the attacker does not control, is how a victim catches an
// account takeover while the pending change can still be undone.
func (s *Sulis) ChangeEmail(ctx context.Context, userID, newEmail string) (string, error) {
	newEmail, err := normalizeEmail(newEmail)
	if err != nil {
		return "", err
	}

	// Checked once up front: staging doesn't make the address live, so a
	// race with another registration here is harmless — ConfirmEmailChange
	// re-checks uniqueness at the point where it actually matters.
	if _, err := s.users.GetUserByEmail(ctx, newEmail); err == nil {
		return "", ErrUserAlreadyExists
	} else if !errors.Is(err, ErrUserNotFound) {
		return "", err
	}

	now := time.Now()
	if _, err := s.updateUserWithRetry(ctx, userID, func(u *User) error {
		u.PendingEmail = newEmail
		u.UpdatedAt = now
		return nil
	}); err != nil {
		return "", err
	}

	return s.createTokenForUserWithEmail(ctx, userID, newEmail, TokenPurposeEmailChange, s.cfg.EmailVerificationTokenDuration)
}

// ConfirmEmailChange consumes a token issued by ChangeEmail. If the token
// still matches the account's currently staged address, it makes that
// address live: Email is swapped in from PendingEmail, PendingEmail is
// cleared, and EmailVerifiedAt is re-stamped with a fresh timestamp — the
// old stamp proved control of the old address, not this one. The swap also
// revokes every session on the account and purges its outstanding
// password-reset and two-factor tokens, since both were minted against (or
// reachable through) the identity that just changed.
//
// Returns ErrTokenInvalid if the token is unknown, expired, already used, of
// the wrong purpose, or bound to an address that is no longer the account's
// PendingEmail — the last case means a later ChangeEmail call has since
// superseded it, and the token for the abandoned address must not still be
// able to claim the account. Returns ErrUserAlreadyExists if another account
// has claimed the staged address since it was staged.
//
// sulis does not send mail. Callers MUST notify the OLD address once this
// succeeds — that is how a victim whose address was just changed out from
// under them learns of it, even though the takeover has already completed.
func (s *Sulis) ConfirmEmailChange(ctx context.Context, rawToken string) (*User, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeEmailChange)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	updated, err := s.updateUserWithRetry(ctx, token.UserID, func(u *User) error {
		// Re-checked against the freshly loaded row on every retry: a later
		// ChangeEmail call may have staged a different address since this
		// token was issued, and this token must not be able to claim it.
		if token.Email != u.PendingEmail {
			return ErrTokenInvalid
		}
		// Re-checked here, not just in ChangeEmail: another account may have
		// claimed this address in the time since it was staged.
		if _, err := s.users.GetUserByEmail(ctx, u.PendingEmail); err == nil {
			return ErrUserAlreadyExists
		} else if !errors.Is(err, ErrUserNotFound) {
			return err
		}
		u.Email = u.PendingEmail
		u.PendingEmail = ""
		u.EmailVerifiedAt = &now
		u.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := s.sessions.DeleteUserSessions(ctx, updated.ID); err != nil {
		return nil, err
	}
	if err := s.tokens.DeleteUserTokens(ctx, updated.ID, TokenPurposePasswordReset); err != nil {
		return nil, err
	}
	if err := s.tokens.DeleteUserTokens(ctx, updated.ID, TokenPurposeTwoFactor); err != nil {
		return nil, err
	}

	return updated, nil
}
