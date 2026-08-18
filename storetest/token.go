package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/borfast/sulis"
)

// RunTokenStore checks an implementation of sulis.TokenStore against the
// contract documented on that interface.
//
// The requirement everything else rests on is ConsumeToken's atomicity: it
// must find the unused token matching hash AND purpose and mark it used as
// one operation, so a token can be redeemed exactly once no matter how many
// callers present it at the same instant. A store that reads the row, checks
// Used, and then writes hands two concurrent callers the same password-reset
// token. The suite also pins the two errors apart — ErrTokenNotFound when
// nothing matches hash+purpose, ErrTokenAlreadyUsed when a match exists but
// was consumed — because sulis maps them to different outcomes, and pins
// purpose scoping, without which a two-factor token would be redeemable as a
// password reset.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunTokenStore(t *testing.T, factory func() sulis.TokenStore) {
	t.Helper()

	ctx := context.Background()

	t.Run("ConsumeTokenReturnsTheStoredToken", func(t *testing.T) {
		store := factory()
		tok := newToken(sulis.TokenPurposePasswordReset)
		tok.Email = uniqueEmail("token-email")
		if err := store.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		got, err := store.ConsumeToken(ctx, tok.TokenHash, tok.Purpose)
		if err != nil {
			t.Fatalf("ConsumeToken: %v", err)
		}
		if got == nil {
			t.Fatal("ConsumeToken returned a nil token and a nil error")
		}
		if got.ID != tok.ID {
			t.Errorf("ID = %q, want %q", got.ID, tok.ID)
		}
		if got.UserID != tok.UserID {
			t.Errorf("UserID = %q, want %q", got.UserID, tok.UserID)
		}
		if got.Purpose != tok.Purpose {
			t.Errorf("Purpose = %q, want %q", got.Purpose, tok.Purpose)
		}
		if got.Email != tok.Email {
			t.Errorf("Email = %q, want %q", got.Email, tok.Email)
		}
	})

	t.Run("ConsumeTokenTwiceReturnsErrTokenAlreadyUsed", func(t *testing.T) {
		store := factory()
		tok := newToken(sulis.TokenPurposeMagicLink)
		if err := store.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		if _, err := store.ConsumeToken(ctx, tok.TokenHash, tok.Purpose); err != nil {
			t.Fatalf("first ConsumeToken: %v", err)
		}

		// The token still exists, so "already used" and not "not found" is
		// the distinction the contract requires.
		_, err := store.ConsumeToken(ctx, tok.TokenHash, tok.Purpose)
		if !errors.Is(err, sulis.ErrTokenAlreadyUsed) {
			t.Fatalf("second ConsumeToken error = %v, want ErrTokenAlreadyUsed", err)
		}
	})

	t.Run("ConsumeTokenUnknownHashReturnsErrTokenNotFound", func(t *testing.T) {
		store := factory()
		_, err := store.ConsumeToken(ctx, uniqueHash("absent"), sulis.TokenPurposePasswordReset)
		if !errors.Is(err, sulis.ErrTokenNotFound) {
			t.Fatalf("ConsumeToken error = %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("ConsumeTokenWrongPurposeReturnsErrTokenNotFound", func(t *testing.T) {
		store := factory()
		tok := newToken(sulis.TokenPurposeTwoFactor)
		if err := store.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		// Purpose is part of the lookup key, not a field checked afterwards:
		// a two-factor token presented to the password-reset flow must not
		// match at all.
		if _, err := store.ConsumeToken(ctx, tok.TokenHash, sulis.TokenPurposePasswordReset); !errors.Is(err, sulis.ErrTokenNotFound) {
			t.Fatalf("ConsumeToken with wrong purpose error = %v, want ErrTokenNotFound", err)
		}

		// And the mismatched attempt must not have consumed anything.
		if _, err := store.ConsumeToken(ctx, tok.TokenHash, sulis.TokenPurposeTwoFactor); err != nil {
			t.Fatalf("ConsumeToken with the right purpose after a mismatch: %v", err)
		}
	})

	t.Run("DeleteExpiredTokensRemovesOnlyExpiredTokens", func(t *testing.T) {
		store := factory()
		expired := newToken(sulis.TokenPurposePasswordReset)
		expired.ExpiresAt = time.Now().Add(-time.Hour)
		live := newToken(sulis.TokenPurposePasswordReset)
		for _, tok := range []*sulis.Token{expired, live} {
			if err := store.CreateToken(ctx, tok); err != nil {
				t.Fatalf("CreateToken: %v", err)
			}
		}

		if err := store.DeleteExpiredTokens(ctx); err != nil {
			t.Fatalf("DeleteExpiredTokens: %v", err)
		}
		if _, err := store.ConsumeToken(ctx, expired.TokenHash, expired.Purpose); !errors.Is(err, sulis.ErrTokenNotFound) {
			t.Fatalf("expired token error after DeleteExpiredTokens = %v, want ErrTokenNotFound", err)
		}
		if _, err := store.ConsumeToken(ctx, live.TokenHash, live.Purpose); err != nil {
			t.Fatalf("unexpired token was removed by DeleteExpiredTokens: %v", err)
		}
	})

	t.Run("DeleteUserTokensRemovesOnlyThatUserAndPurpose", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		otherID := uniqueID("user")

		target := newTokenFor(userID, sulis.TokenPurposePasswordReset)
		otherPurpose := newTokenFor(userID, sulis.TokenPurposeTwoFactor)
		otherUser := newTokenFor(otherID, sulis.TokenPurposePasswordReset)
		for _, tok := range []*sulis.Token{target, otherPurpose, otherUser} {
			if err := store.CreateToken(ctx, tok); err != nil {
				t.Fatalf("CreateToken: %v", err)
			}
		}

		if err := store.DeleteUserTokens(ctx, userID, sulis.TokenPurposePasswordReset); err != nil {
			t.Fatalf("DeleteUserTokens: %v", err)
		}
		if _, err := store.ConsumeToken(ctx, target.TokenHash, target.Purpose); !errors.Is(err, sulis.ErrTokenNotFound) {
			t.Fatalf("targeted token error = %v, want ErrTokenNotFound", err)
		}
		if _, err := store.ConsumeToken(ctx, otherPurpose.TokenHash, otherPurpose.Purpose); err != nil {
			t.Fatalf("another purpose for the same user was deleted: %v", err)
		}
		if _, err := store.ConsumeToken(ctx, otherUser.TokenHash, otherUser.Purpose); err != nil {
			t.Fatalf("another user's token was deleted: %v", err)
		}
	})

	t.Run("DeleteUserTokensMatchingNothingIsNotAnError", func(t *testing.T) {
		store := factory()
		if err := store.DeleteUserTokens(ctx, uniqueID("user"), sulis.TokenPurposeEmailChange); err != nil {
			t.Fatalf("DeleteUserTokens with nothing to delete: %v", err)
		}
	})

	t.Run("ConcurrentConsumeTokenHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			tok := newToken(sulis.TokenPurposePasswordReset)
			if err := store.CreateToken(ctx, tok); err != nil {
				t.Fatalf("iteration %d: CreateToken: %v", i, err)
			}

			consumed := make([]*sulis.Token, racers)
			errs := race(racers, func(g int) error {
				got, err := store.ConsumeToken(ctx, tok.TokenHash, tok.Purpose)
				consumed[g] = got
				return err
			})

			// Every loser must see ErrTokenAlreadyUsed rather than
			// ErrTokenNotFound: the token exists throughout, so "no token
			// matches hash+purpose" would be a lie.
			winner := exactlyOneWinner(t, errs, sulis.ErrTokenAlreadyUsed,
				fmt.Sprintf("iteration %d: concurrent ConsumeToken", i))
			if consumed[winner] == nil {
				t.Fatalf("iteration %d: the winning ConsumeToken returned a nil token", i)
			}
			for g, got := range consumed {
				if g != winner && got != nil {
					t.Fatalf("iteration %d: goroutine %d failed but still received a token — a failed consume must hand back nothing", i, g)
				}
			}
		}
	})
}

// newToken builds a token for a fresh user with a unique hash, expiring far
// enough in the future that DeleteExpiredTokens leaves it alone.
func newToken(purpose sulis.TokenPurpose) *sulis.Token {
	return newTokenFor(uniqueID("user"), purpose)
}

func newTokenFor(userID string, purpose sulis.TokenPurpose) *sulis.Token {
	now := time.Now()
	return &sulis.Token{
		ID:        uniqueID("token"),
		UserID:    userID,
		TokenHash: uniqueHash("token"),
		Purpose:   purpose,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}
