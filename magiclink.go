package sulis

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// magicLinkNonceBytes is the length, in bytes, of the random binding nonce
// generated alongside a magic-link token when WithMagicLinkBinding is
// enabled (the default). It is sized independently of ResetTokenBytes,
// which sizes the token itself: the nonce's job is to tie redemption to
// the browser that requested the link (via a short-lived cookie — see
// WithMagicLinkBinding), not to carry standalone entropy toward a remote
// attacker, so it does not need to match the token's size to be effective.
const magicLinkNonceBytes = 16

// CreateMagicLinkToken generates a magic link token for the given email and,
// when magic-link binding is enabled (WithMagicLinkBinding, on by default),
// a companion binding nonce. If no user exists for the email, the token is
// issued without creating a user row — the user is created at redemption
// time (see RedeemMagicLink) so that requesting magic links for arbitrary
// addresses cannot be used to flood the user store before anything is ever
// delivered. The raw token is returned so the consumer can deliver it (e.g.
// via email).
//
// The raw bindingNonce, when non-empty, must be set by the caller as a
// short-lived, HttpOnly cookie on the response to THIS request — never
// embedded in the emailed link itself — and read back from that cookie when
// the link is later clicked, to pass to RedeemMagicLink alongside the token
// recovered from the link. See WithMagicLinkBinding for the full wiring,
// the reasoning, and the empty-string case when binding is disabled.
func (s *Sulis) CreateMagicLinkToken(ctx context.Context, email string, ri RequestInfo) (token, bindingNonce string, err error) {
	email, err = normalizeEmail(email)
	if err != nil {
		return "", "", err
	}

	if err := s.allow(ctx, "magic:"+email); err != nil {
		return "", "", err
	}
	if err := s.allowIP(ctx, "magic:", ri); err != nil {
		return "", "", err
	}

	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return "", "", err
		}
		return s.issueMagicLinkToken(ctx, "", email)
	}

	return s.issueMagicLinkToken(ctx, user.ID, "")
}

// issueMagicLinkToken creates and stores a magic-link Token for either an
// existing user (userID set, email empty) or an email with no user yet
// (userID empty, email set — the user is created lazily at redemption; see
// getOrCreatePasswordlessUser). It always uses MagicLinkDuration, never
// TokenDuration (which governs password-reset tokens only), and — when
// s.cfg.MagicLinkBinding is enabled — generates a random binding nonce,
// storing only its SHA-256 hash (Token.NonceHash) and returning the raw
// nonce for the caller to set as a cookie. When binding is disabled,
// bindingNonce is "" and the stored token carries no NonceHash at all.
func (s *Sulis) issueMagicLinkToken(ctx context.Context, userID, email string) (raw, bindingNonce string, err error) {
	raw, hashed, err := generateRawToken(s.cfg.ResetTokenBytes)
	if err != nil {
		return "", "", fmt.Errorf("sulis: generating token: %w", err)
	}

	var nonceHash string
	if s.cfg.MagicLinkBinding {
		bindingNonce, nonceHash, err = generateRawToken(magicLinkNonceBytes)
		if err != nil {
			return "", "", fmt.Errorf("sulis: generating binding nonce: %w", err)
		}
	}

	now := time.Now()
	tok := &Token{
		ID:        generateID(),
		UserID:    userID,
		Email:     email,
		TokenHash: hashed,
		NonceHash: nonceHash,
		Purpose:   TokenPurposeMagicLink,
		ExpiresAt: now.Add(s.cfg.MagicLinkDuration),
		CreatedAt: now,
	}

	if err := s.tokens.CreateToken(ctx, tok); err != nil {
		return "", "", err
	}

	return raw, bindingNonce, nil
}

// RedeemMagicLink validates a magic link token and, when the token carries a
// stored NonceHash (magic-link binding was enabled at issuance — see
// WithMagicLinkBinding, on by default), the bindingNonce that must
// accompany it. If the token was issued before the user existed, the user
// is created now, as a passwordless account.
//
// bindingNonce must equal the raw nonce CreateMagicLinkToken returned
// alongside this same rawToken (compared via its SHA-256 hash, in constant
// time via crypto/subtle.ConstantTimeCompare) — typically recovered from
// the short-lived HttpOnly cookie the application set at issuance time; see
// WithMagicLinkBinding for the full wiring and reasoning. A missing or
// wrong bindingNonce is rejected with ErrTokenInvalid, exactly like a
// missing or wrong token, so neither leaks which half was the problem.
// When the token carries no NonceHash — binding was disabled when it was
// issued — any bindingNonce is accepted, including "".
//
// The binding check runs AFTER the token is consumed (see consumeToken): a
// wrong nonce still burns the token, the same fail-safe direction expiry is
// already checked in. This is deliberate — a magic link is single-use
// regardless of which half of the (token, nonce) pair was wrong, so an
// attacker who obtains a token but not its nonce cannot keep retrying
// nonces against the same still-live token.
//
// A magic link is a FULL first factor — proving control of the mailbox is
// equivalent to knowing the password — so it is gated by two-factor
// authentication exactly like Login. If the account has a second factor
// enrolled, the returned LoginResult carries a PendingToken rather than a
// session. Without this, anyone able to read the mailbox would bypass 2FA
// entirely, which is precisely the attacker a second factor exists to stop.
func (s *Sulis) RedeemMagicLink(ctx context.Context, rawToken, bindingNonce string, ri RequestInfo) (*LoginResult, error) {
	tok, err := s.consumeToken(ctx, rawToken, TokenPurposeMagicLink)
	if err != nil {
		return nil, err
	}

	if tok.NonceHash != "" {
		if bindingNonce == "" ||
			subtle.ConstantTimeCompare([]byte(hashToken(bindingNonce)), []byte(tok.NonceHash)) != 1 {
			return nil, ErrTokenInvalid
		}
	}

	var user *User
	if tok.UserID != "" {
		user, err = s.users.GetUserByID(ctx, tok.UserID)
	} else {
		user, err = s.getOrCreatePasswordlessUser(ctx, tok.Email)
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

	return s.completeFirstFactor(ctx, user, AuthMethodMagicLink, ri)
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
