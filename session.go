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
	Metadata  map[string]any
}

// SessionStore defines the persistence operations for sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpired(ctx context.Context) error
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
