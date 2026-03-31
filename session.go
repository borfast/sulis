package sulis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Session represents a server-side authentication session.
type Session struct {
	ID        string
	UserID    string
	Token     string // opaque, cryptographically random token
	ExpiresAt time.Time
	CreatedAt time.Time
	Metadata  map[string]any
}

// SessionStore defines the persistence operations for sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByToken(ctx context.Context, token string) (*Session, error)
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
