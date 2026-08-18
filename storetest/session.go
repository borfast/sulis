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
		if got.Method != sess.Method {
			t.Errorf("Method = %q, want %q", got.Method, sess.Method)
		}
		if got.AuthenticatedAt.IsZero() {
			t.Error("AuthenticatedAt is the zero time — RequireRecentAuth would fail closed on a session that was actually just issued")
		}
		if got.LastSeenAt.IsZero() {
			t.Error("LastSeenAt is the zero time — a session that was actually just issued should already have one")
		}
		if got.IP != sess.IP {
			t.Errorf("IP = %q, want %q", got.IP, sess.IP)
		}
		if got.UserAgent != sess.UserAgent {
			t.Errorf("UserAgent = %q, want %q", got.UserAgent, sess.UserAgent)
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

	t.Run("UpdateAuthenticatedAtStampsTheStoredSession", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		old := time.Now().Add(-2 * time.Hour)
		sess.AuthenticatedAt = old
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		fresh := time.Now()
		if err := store.UpdateAuthenticatedAt(ctx, sess.ID, fresh); err != nil {
			t.Fatalf("UpdateAuthenticatedAt: %v", err)
		}

		got, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if !got.AuthenticatedAt.After(old) {
			t.Fatalf("AuthenticatedAt = %v, want a time after %v", got.AuthenticatedAt, old)
		}
		// Nothing else about the session should move.
		if got.ID != sess.ID || got.UserID != sess.UserID || got.TokenHash != sess.TokenHash {
			t.Fatalf("UpdateAuthenticatedAt changed identity fields: got %+v", got)
		}
		if !got.ExpiresAt.Equal(sess.ExpiresAt) {
			t.Fatalf("UpdateAuthenticatedAt changed ExpiresAt: got %v, want %v", got.ExpiresAt, sess.ExpiresAt)
		}
	})

	t.Run("UpdateAuthenticatedAtUnknownIDReturnsErrSessionNotFound", func(t *testing.T) {
		store := factory()
		if err := store.UpdateAuthenticatedAt(ctx, uniqueID("session"), time.Now()); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("UpdateAuthenticatedAt for an unknown session error = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("ReturnedSessionsAreIndependentOfStoredState", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		sess.Metadata = map[string]any{"device": "laptop"}
		wantUser := sess.UserID
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		read, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		read.UserID = uniqueID("hijacked")
		// A struct copy copies a map header, not the map, so a store that
		// does not clone Metadata hands every reader a live handle on the
		// stored session.
		mutateMetadata(read.Metadata)

		after, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if after.UserID != wantUser {
			t.Fatalf("mutating the value returned by GetSessionByTokenHash changed the stored UserID to %q — a session whose owner a caller can rewrite is an account takeover",
				after.UserID)
		}
		assertMetadataUnchanged(t, "GetSessionByTokenHash", after.Metadata, "device", "laptop")

		sess.UserID = uniqueID("hijacked")
		mutateMetadata(sess.Metadata)

		final, err := store.GetSessionByTokenHash(ctx, after.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if final.UserID != wantUser {
			t.Fatalf("mutating the *Session passed to CreateSession changed the stored UserID to %q", final.UserID)
		}
		assertMetadataUnchanged(t, "CreateSession", final.Metadata, "device", "laptop")
	})

	t.Run("TouchSessionUpdatesLastSeenAndIdleExpires", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		lastSeen := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		idleExpires := lastSeen.Add(30 * time.Minute)
		if err := store.TouchSession(ctx, sess.ID, lastSeen, &idleExpires); err != nil {
			t.Fatalf("TouchSession: %v", err)
		}

		got, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if !got.LastSeenAt.Equal(lastSeen) {
			t.Errorf("LastSeenAt = %v, want %v", got.LastSeenAt, lastSeen)
		}
		if got.IdleExpiresAt == nil || !got.IdleExpiresAt.Equal(idleExpires) {
			t.Errorf("IdleExpiresAt = %v, want %v", got.IdleExpiresAt, idleExpires)
		}
		// Nothing else about the session should move.
		if got.ID != sess.ID || got.UserID != sess.UserID || got.TokenHash != sess.TokenHash {
			t.Fatalf("TouchSession changed identity fields: got %+v", got)
		}
		if !got.ExpiresAt.Equal(sess.ExpiresAt) {
			t.Fatalf("TouchSession changed ExpiresAt: got %v, want %v", got.ExpiresAt, sess.ExpiresAt)
		}
		if !got.AuthenticatedAt.Equal(sess.AuthenticatedAt) {
			t.Fatalf("TouchSession changed AuthenticatedAt: got %v, want %v", got.AuthenticatedAt, sess.AuthenticatedAt)
		}
	})

	t.Run("TouchSessionCanClearIdleExpiresAtBackToNil", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		firstIdle := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		if err := store.TouchSession(ctx, sess.ID, firstIdle, &firstIdle); err != nil {
			t.Fatalf("TouchSession (set): %v", err)
		}

		lastSeen := firstIdle.Add(time.Minute)
		if err := store.TouchSession(ctx, sess.ID, lastSeen, nil); err != nil {
			t.Fatalf("TouchSession (clear): %v", err)
		}

		got, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if got.IdleExpiresAt != nil {
			t.Fatalf("IdleExpiresAt = %v, want nil after a TouchSession call passing nil — a disabled idle timeout must not leave a stale deadline lingering", got.IdleExpiresAt)
		}
	})

	t.Run("TouchSessionIdleExpiresAtIsNotAliased", func(t *testing.T) {
		store := factory()
		sess := newSession(uniqueID("user"))
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		idleExpires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		if err := store.TouchSession(ctx, sess.ID, idleExpires, &idleExpires); err != nil {
			t.Fatalf("TouchSession: %v", err)
		}

		read, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if read.IdleExpiresAt != nil {
			// Mutating the pointee on a value returned by the store must not
			// reach the stored row — the same aliasing trap Metadata already
			// guards against above, and IdleExpiresAt is a pointer for the
			// same reason: a session whose expiry a caller can rewrite
			// outside TouchSession is a session that never expires.
			*read.IdleExpiresAt = time.Unix(0, 0).UTC()
		}

		reread, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if reread.IdleExpiresAt != nil && reread.IdleExpiresAt.Equal(time.Unix(0, 0).UTC()) {
			t.Fatal("mutating *IdleExpiresAt on the value returned by GetSessionByTokenHash changed stored state — the pointer must not be shared with the store")
		}
	})

	t.Run("TouchSessionUnknownIDReturnsErrSessionNotFound", func(t *testing.T) {
		store := factory()
		future := time.Now().Add(time.Hour)
		if err := store.TouchSession(ctx, uniqueID("session"), time.Now(), &future); !errors.Is(err, sulis.ErrSessionNotFound) {
			t.Fatalf("TouchSession for an unknown session error = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("ListUserSessionsReturnsOnlyThatUsersSessions", func(t *testing.T) {
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

		got, err := store.ListUserSessions(ctx, userID)
		if err != nil {
			t.Fatalf("ListUserSessions: %v", err)
		}
		if len(got) != len(mine) {
			t.Fatalf("ListUserSessions returned %d sessions, want %d", len(got), len(mine))
		}
		wantIDs := map[string]bool{mine[0].ID: true, mine[1].ID: true}
		for _, sess := range got {
			if !wantIDs[sess.ID] {
				t.Errorf("ListUserSessions returned unexpected session %q", sess.ID)
			}
			if sess.UserID != userID {
				t.Errorf("ListUserSessions returned session for UserID %q, want %q", sess.UserID, userID)
			}
			if sess.ID == theirs.ID {
				t.Error("ListUserSessions returned another user's session")
			}
		}
	})

	t.Run("ListUserSessionsMatchingNothingReturnsEmptyNotError", func(t *testing.T) {
		store := factory()
		got, err := store.ListUserSessions(ctx, uniqueID("user"))
		if err != nil {
			t.Fatalf("ListUserSessions: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("ListUserSessions for a user with no sessions returned %d sessions, want 0", len(got))
		}
	})

	t.Run("ListUserSessionsReturnedSessionsAreIndependentOfStoredState", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		sess := newSession(userID)
		sess.Metadata = map[string]any{"device": "laptop"}
		if err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		got, err := store.ListUserSessions(ctx, userID)
		if err != nil {
			t.Fatalf("ListUserSessions: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("ListUserSessions returned %d sessions, want 1", len(got))
		}
		got[0].UserID = uniqueID("hijacked")
		mutateMetadata(got[0].Metadata)

		after, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
		if err != nil {
			t.Fatalf("GetSessionByTokenHash: %v", err)
		}
		if after.UserID != userID {
			t.Fatalf("mutating a *Session returned by ListUserSessions changed the stored UserID to %q", after.UserID)
		}
		assertMetadataUnchanged(t, "ListUserSessions", after.Metadata, "device", "laptop")
	})

	t.Run("DeleteUserSessionsExceptRemovesOnlyOtherSessionsForThatUser", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		keep := newSession(userID)
		others := []*sulis.Session{newSession(userID), newSession(userID)}
		otherUser := newSession(uniqueID("user"))
		for _, sess := range append(append([]*sulis.Session{keep}, others...), otherUser) {
			if err := store.CreateSession(ctx, sess); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
		}

		if err := store.DeleteUserSessionsExcept(ctx, userID, keep.ID); err != nil {
			t.Fatalf("DeleteUserSessionsExcept: %v", err)
		}

		if _, err := store.GetSessionByTokenHash(ctx, keep.TokenHash); err != nil {
			t.Fatalf("kept session was removed by DeleteUserSessionsExcept: %v", err)
		}
		for _, sess := range others {
			if _, err := store.GetSessionByTokenHash(ctx, sess.TokenHash); !errors.Is(err, sulis.ErrSessionNotFound) {
				t.Fatalf("session %q survived DeleteUserSessionsExcept: %v", sess.ID, err)
			}
		}
		if _, err := store.GetSessionByTokenHash(ctx, otherUser.TokenHash); err != nil {
			t.Fatalf("another user's session was removed by DeleteUserSessionsExcept: %v", err)
		}
	})

	t.Run("DeleteUserSessionsExceptUnknownKeepIDStillRemovesTheRest", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		sessions := []*sulis.Session{newSession(userID), newSession(userID)}
		for _, sess := range sessions {
			if err := store.CreateSession(ctx, sess); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
		}

		// keepSessionID names nothing at all — every session for userID
		// still counts as an "other" and is removed. Matches
		// DeleteUserSessions's "matching nothing is not an error" behavior
		// for the degenerate all-sessions case.
		if err := store.DeleteUserSessionsExcept(ctx, userID, uniqueID("session")); err != nil {
			t.Fatalf("DeleteUserSessionsExcept: %v", err)
		}
		for _, sess := range sessions {
			if _, err := store.GetSessionByTokenHash(ctx, sess.TokenHash); !errors.Is(err, sulis.ErrSessionNotFound) {
				t.Fatalf("session %q survived DeleteUserSessionsExcept with an unknown keepSessionID: %v", sess.ID, err)
			}
		}
	})

	t.Run("DeleteUserSessionsExceptMatchingNothingIsNotAnError", func(t *testing.T) {
		store := factory()
		if err := store.DeleteUserSessionsExcept(ctx, uniqueID("user"), uniqueID("session")); err != nil {
			t.Fatalf("DeleteUserSessionsExcept with nothing to delete: %v", err)
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
		ID:              uniqueID("session"),
		UserID:          userID,
		TokenHash:       uniqueHash("session"),
		ExpiresAt:       now.Add(time.Hour),
		CreatedAt:       now,
		AuthenticatedAt: now,
		Method:          sulis.AuthMethodPassword,
		LastSeenAt:      now,
		IP:              "203.0.113.7",
		UserAgent:       "storetest-agent/1.0",
	}
}
