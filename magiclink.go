package sulis

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CreateMagicLinkToken generates a magic link token for the given email. If
// no user exists for the email, the token is issued without creating a user
// row — the user is created at redemption time (see RedeemMagicLink) so that
// requesting magic links for arbitrary addresses cannot be used to flood the
// user store before anything is ever delivered. The raw token is returned so
// the consumer can deliver it (e.g. via email).
func (s *Sulis) CreateMagicLinkToken(ctx context.Context, email string, ri RequestInfo) (string, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return "", err
	}

	if err := s.allow(ctx, "magic:"+email); err != nil {
		return "", err
	}
	if err := s.allowIP(ctx, "magic:", ri); err != nil {
		return "", err
	}

	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return "", err
		}
		return s.createMagicLinkTokenForEmail(ctx, email)
	}

	return s.createTokenForUser(ctx, user.ID, TokenPurposeMagicLink, s.cfg.TokenDuration)
}

// createMagicLinkTokenForEmail issues a magic-link token for an email with no
// existing user, deferring user creation until the token is redeemed.
func (s *Sulis) createMagicLinkTokenForEmail(ctx context.Context, email string) (string, error) {
	raw, hashed, err := generateRawToken(s.cfg.ResetTokenBytes)
	if err != nil {
		return "", fmt.Errorf("sulis: generating token: %w", err)
	}

	now := time.Now()
	token := &Token{
		ID:        generateID(),
		Email:     email,
		TokenHash: hashed,
		Purpose:   TokenPurposeMagicLink,
		ExpiresAt: now.Add(s.cfg.TokenDuration),
		CreatedAt: now,
	}

	if err := s.tokens.CreateToken(ctx, token); err != nil {
		return "", err
	}

	return raw, nil
}

// RedeemMagicLink validates a magic link token. If the token was issued before
// the user existed, the user is created now, as a passwordless account.
//
// A magic link is a FULL first factor — proving control of the mailbox is
// equivalent to knowing the password — so it is gated by two-factor
// authentication exactly like Login. If the account has a second factor
// enrolled, the returned LoginResult carries a PendingToken rather than a
// session. Without this, anyone able to read the mailbox would bypass 2FA
// entirely, which is precisely the attacker a second factor exists to stop.
func (s *Sulis) RedeemMagicLink(ctx context.Context, rawToken string, ri RequestInfo) (*LoginResult, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeMagicLink)
	if err != nil {
		return nil, err
	}

	var user *User
	if token.UserID != "" {
		user, err = s.users.GetUserByID(ctx, token.UserID)
	} else {
		user, err = s.getOrCreatePasswordlessUser(ctx, token.Email)
	}
	if err != nil {
		return nil, err
	}

	// Redeeming a magic link proves control of the mailbox, so treat it as
	// email verification too. This must happen BEFORE the second-factor
	// branch: completeFirstFactor enforces RequireVerifiedEmail, so a
	// 2FA-enabled user could otherwise never verify their address this way.
	if err := s.stampEmailVerified(ctx, user); err != nil {
		return nil, err
	}

	return s.completeFirstFactor(ctx, user, AuthMethodMagicLink)
}

// getOrCreatePasswordlessUser looks up a user by email, creating a
// passwordless user if none exists yet. If another request won the race and
// created the user first (CreateUser returns ErrUserAlreadyExists), the
// lookup is retried so the caller logs into that account instead of failing.
func (s *Sulis) getOrCreatePasswordlessUser(ctx context.Context, email string) (*User, error) {
	user, err := s.users.GetUserByEmail(ctx, email)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}

	now := time.Now()
	user = &User{
		ID:        generateID(),
		Email:     email,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.users.CreateUser(ctx, user); err != nil {
		if errors.Is(err, ErrUserAlreadyExists) {
			return s.users.GetUserByEmail(ctx, email)
		}
		return nil, err
	}
	return user, nil
}
