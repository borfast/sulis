package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/borfast/sulis"
)

// RunSessionStore checks an implementation of sulis.SessionStore against the
// contract documented on that interface.
//
// The requirement worth the most here is DeleteSession's scoping: the
// membership check and the removal must be one operation keyed on both the
// session ID and the owning user, and zero rows affected — whether the ID does
// not exist or exists but belongs to someone else — must return
// ErrSessionNotFound rather than succeeding silently. That is what makes
// cross-user revocation impossible through Sulis.RevokeSession, which passes
// the caller's own user ID: a store that ignores the user ID, or that reports
// success when it deleted nothing, hands an attacker who learns a session ID
// the power to sign other people out.
//
// Sessions are looked up by token hash, never by raw token; the suite stores
// only hashes, the same as sulis does.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunSessionStore(t *testing.T, factory func() sulis.SessionStore) {
	t.Helper()

	ctx := context.Background()

	t.Run("CreateSessionRoundTripsByTokenHash", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		got, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if got == nil {
			t.Fatal("GetSessionByTokenHash returned a nil session and a nil error")
		}
		if got.ID != sess.ID {
			t.Errorf("ID = %q, want %q", got.ID, sess.ID)
		}
		if got.UserID != sess.UserID {
			t.Errorf("UserID = %q, want %q", got.UserID, sess.UserID)
		}
		if got.TokenHash != sess.TokenHash {
			t.Errorf("TokenHash = %q, want %q", got.TokenHash, sess.TokenHash)
		}
		if got.ExpiresAt.IsZero() {
			t.Error("ExpiresAt is the zero time — a session with no expiry never expires")
		}
	})

	t.Run("GetSessionByTokenHashUnknownReturnsErrSessionNotFound", func(t *testing.T) {
		store := factory()
		if _, err := store.GetSessionByTokenHash(ctx, uniqueHash("absent")); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("GetSessionByTokenHash error = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("DeleteSessionRemovesTheOwnersSession", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		if err := store.DeleteSession(ctx, sess.UserID, sess.ID); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if _, err := store.GetSessionByTokenHash(ctx, sess.TokenHash); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("GetSessionByTokenHash after delete = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("DeleteSessionForAnotherUserReturnsErrSessionNotFoundAndKeepsTheSession", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("owner"))
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		attacker := uniqueID("attacker")
		if err := store.DeleteSession(ctx, attacker, sess.ID); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("cross-user DeleteSession error = %v, want ErrSessionNotFound", err)
		}
		// Reporting the refusal is only half of it: the session must still be
		// there, or a leaked session ID would still sign the owner out.
		if _, err := store.GetSessionByTokenHash(ctx, sess.TokenHash); err != nil {
			t.Fatalf("the owner's session was removed by another user's DeleteSession: %v", err)
		}
	})

	t.Run("DeleteSessionUnknownIDReturnsErrSessionNotFound", func(t *testing.T) {
		store := factory()
		if err := store.DeleteSession(ctx, uniqueID("user"), uniqueID("session")); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("DeleteSession for an unknown session error = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("DeleteUserSessionsRemovesOnlyThatUsersSessions", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		otherID := uniqueID("user")
		mine := []*sulis.Session{newSession(userID), newSession(userID)}
		theirs := newSession(otherID)
		for _, sess := range append(append([]*sulis.Session{}, mine...), theirs) {
			if err := store.CreateSession(ctx, sess); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
		}

		if err := store.DeleteUserSessions(ctx, userID); err != nil {
			t.Fatalf("DeleteUserSessions: %v", err)
		}
		for _, sess := range mine {
			if _, err := store.GetSessionByTokenHash(ctx, sess.TokenHash); !errors.Is(err, sulis.ErrSessionNotFound) {
				t.Fatalf("session %q survived DeleteUserSessions: %v", sess.ID, err)
			}
		}
		if _, err := store.GetSessionByTokenHash(ctx, theirs.TokenHash); err != nil {
			t.Fatalf("another user's session was removed by DeleteUserSessions: %v", err)
		}
	})

	t.Run("DeleteUserSessionsMatchingNothingIsNotAnError", func(t *testing.T) {
		store := factory()
		if err := store.DeleteUserSessions(ctx, uniqueID("user")); err != nil {
			t.Fatalf("DeleteUserSessions with nothing to delete: %v", err)
		}
	})

	t.Run("CleanExpiredRemovesOnlyExpiredSessions", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		expired := newSession(userID)
		expired.ExpiresAt = time.Now().Add(-time.Hour)
		live := newSession(userID)
		for _, sess := range []*sulis.Session{expired, live} {
			if err := store.CreateSession(ctx, sess); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
		}

		if err := store.CleanExpired(ctx); err != nil {
			t.Fatalf("CleanExpired: %v", err)
		}
		if _, err := store.GetSessionByTokenHash(ctx, expired.TokenHash); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("expired session after CleanExpired = %v, want ErrSessionNotFound", err)
		}
		if _, err := store.GetSessionByTokenHash(ctx, live.TokenHash); err != nil {
			t.Fatalf("unexpired session was removed by CleanExpired: %v", err)
		}
	})

	t.Run("ReturnedSessionsAreIndependentOfStoredState", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		wantUser := sess.UserID
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		read, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		read.UserID = uniqueID("hijacked")

		after, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if after.UserID != wantUser {
			t.Fatalf("mutating the value returned by GetSessionByTokenHash changed the stored UserID to %q — a session whose owner a caller can rewrite is an account takeover",
				after.UserID)
		}

		sess.UserID = uniqueID("hijacked")
		final, err := store.GetSessionByTokenHash(ctx, after.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if final.UserID != wantUser {
			t.Fatalf("mutating the *Session passed to CreateSession changed the stored UserID to %q", final.UserID)
		}
	})

	t.Run("ConcurrentDeleteSessionHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			sess := newSession(uniqueID("user"))
			if err := store.CreateSession(ctx, sess); err != nil {
				t.Fatalf("iteration %d: CreateSession: %v", i, err)
			}

			// Only one caller can have affected a row, so only one may report
			// success. A store that deletes and reports nil regardless tells
			// every caller it revoked a session that was already gone.
			errs := race(racers, func(int) error {
				return store.DeleteSession(ctx, sess.UserID, sess.ID)
			})
			exactlyOneWinner(t, errs, sulis.ErrSessionNotFound,
				fmt.Sprintf("iteration %d: concurrent DeleteSession", i))
		}
	})
}

// newSession builds a live session for userID with a unique ID and token hash.
func newSession(userID string) *sulis.Session {
	now := time.Now()
	return &sulis.Session{
		ID:        uniqueID("session"),
		UserID:    userID,
		TokenHash: uniqueHash("session"),
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}
