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

	if err := s.allow(ctx, "magic:"+email, ri); err != nil {
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

	// UserID is empty when the address has no account yet — the token is
	// issued anyway and the user is created at redemption (see
	// getOrCreatePasswordlessUser). The address itself is not carried; a
	// magic link for an unregistered address is still visible as a
	// created-without-a-user event, and as an EventRateLimitTripped on the
	// "magic" scope if somebody is doing it in bulk.
	s.emit(ctx, Event{Kind: EventMagicLinkCreated, UserID: userID})

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
// The binding check runs AFTER the token is consumed (see consumeToken),
// primarily because consumeToken's atomicity contract — one indivisible
// find-and-mark-used operation — has no room for a nonce check in the
// middle of it without either breaking that atomicity (a check-first design
// would need to read the row, check the nonce, and mark it used as three
// separate steps, reopening exactly the TOCTOU consumeToken's single
// operation exists to close) or widening TokenStore.ConsumeToken to accept
// and verify a nonce hash itself, a larger interface change this task does
// not make. A secondary effect of the ordering, the same fail-safe
// direction expiry is already checked in: a wrong nonce still burns the
// token, so an attacker who obtains a token but not its nonce gets exactly
// one attempt rather than unlimited retries against a token that stays
// live — though with a 128-bit nonce, guessing was never the realistic
// threat this closes; the atomicity constraint is.
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
		s.emitMagicLinkRejected(ctx, "", ri, tokenReason(err))
		return nil, err
	}

	if tok.NonceHash != "" {
		if bindingNonce == "" ||
			subtle.ConstantTimeCompare([]byte(hashToken(bindingNonce)), []byte(tok.NonceHash)) != 1 {
			// The most interesting event in this file: the token was
			// genuine and the browser presenting it was not the one that
			// asked for the link. A forwarded, prefetched, or stolen link
			// looks exactly like this.
			s.emitMagicLinkRejected(ctx, tok.UserID, ri, ReasonBindingMismatch)
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

	// The mailbox is proven at this point: the token was valid, single-use,
	// and (when binding was on) presented by the browser that asked for it.
	// This is the magic-link counterpart of EventLoginSucceeded, and like it
	// it does not mean a session followed — completeFirstFactor below may
	// still demand a second factor or refuse the account outright.
	s.emit(ctx, Event{
		Kind:        EventMagicLinkRedeemed,
		UserID:      user.ID,
		RequestInfo: ri,
	})

	// Redeeming a magic link proves control of the mailbox, so treat it as
	// email verification too. This must happen BEFORE the second-factor
	// branch: completeFirstFactor enforces RequireVerifiedEmail, so a
	// 2FA-enabled user could otherwise never verify their address this way.
	if err := s.stampEmailVerified(ctx, user); err != nil {
		return nil, err
	}

	return s.completeFirstFactor(ctx, user, AuthMethodMagicLink, ri)
}

// emitMagicLinkRejected reports a refused RedeemMagicLink. userID is empty
// when the token did not resolve to one — an unknown, expired, or
// already-used token names nobody.
func (s *Sulis) emitMagicLinkRejected(ctx context.Context, userID string, ri RequestInfo, reason string) {
	s.emit(ctx, Event{
		Kind:        EventMagicLinkRejected,
		UserID:      userID,
		RequestInfo: ri,
	}, string(MetaReason), reason)
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
