package sulis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Session represents a server-side authentication session.
type Session struct {
	ID     string
	UserID string
	// TokenHash is the SHA-256 hash of the session token. The raw token is
	// never a field on this struct: it is returned beside the *Session at
	// issue time and nowhere else, so no store can persist it by accident.
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	// AuthenticatedAt is when the credential behind this session was last
	// proven — at issuance, and again on every successful ReAuthenticate.
	// RequireRecentAuth compares it against a caller-supplied maxAge to gate
	// security-sensitive operations (enrolling or replacing a second
	// factor, removing a passkey, disabling 2FA, changing email,
	// regenerating recovery codes — see the README) behind more than a
	// bare, possibly hours-old session. A session issued before this field
	// existed reads back as the zero time, which is always older than any
	// maxAge, so RequireRecentAuth fails closed on it rather than treating
	// an absent stamp as fresh.
	AuthenticatedAt time.Time
	// Method records which credential last authenticated this session —
	// set at issuance from the AuthMethod the caller vouches for (or, for
	// IssueSession, the one recorded on the Authentication proof) and left
	// untouched by ReAuthenticate, which refreshes AuthenticatedAt only.
	Method   AuthMethod
	Metadata map[string]any
}

// SessionStore defines the persistence operations for sessions.
//
// A store MUST NOT share mutable state with its callers in either direction.
// Metadata is a map, so copying a *Session with a plain struct assignment
// copies a map header rather than the map, leaving the caller holding a live
// handle on the stored session — and a session a caller can rewrite outside
// CreateSession is a session whose UserID a caller can rewrite. Copy the map
// (one level is enough) when storing a session and when returning one. Stores
// that reconstruct rows from a database read get this for free; in-memory ones
// do not. storetest.RunSessionStore checks it.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)

	// DeleteSession removes the session identified by id if it belongs to
	// userID. The membership check and the removal MUST happen as a
	// single atomic operation scoped to both columns:
	//
	//	DELETE FROM sessions WHERE id = ? AND user_id = ?
	//
	// Zero rows affected — whether id does not exist at all, or exists
	// but belongs to a different user — MUST return ErrSessionNotFound
	// rather than succeeding silently. This is what makes cross-user
	// revocation impossible through RevokeSession: it passes the
	// caller's own userID, so guessing or leaking another user's session
	// ID never deletes anything.
	DeleteSession(ctx context.Context, userID, id string) error

	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpired(ctx context.Context) error

	// UpdateAuthenticatedAt stamps the session identified by id with at,
	// leaving every other field (including ExpiresAt and Method) untouched:
	//
	//	UPDATE sessions SET authenticated_at = ? WHERE id = ?
	//
	// Zero rows affected — id does not exist — MUST return
	// ErrSessionNotFound. This is the write path behind ReAuthenticate: it
	// refreshes how recently a session's owner last proved their
	// credential, without minting a new session or rotating its token, so
	// a subsequent RequireRecentAuth call passes immediately afterward.
	//
	// It is deliberately its own method rather than an extra parameter on
	// the session-liveness "last seen" touch a future task adds: a step-up
	// re-authentication and a liveness heartbeat are different events with
	// different callers and different frequencies, and folding them into
	// one call would make a caller that means to refresh only one of the
	// two silently refresh both.
	UpdateAuthenticatedAt(ctx context.Context, id string, at time.Time) error
}

// generateSessionToken creates a cryptographically random session token.
func generateSessionToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sulis: generating session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashSessionToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
