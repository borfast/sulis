package sulis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// TokenPurpose identifies the intended use of a token.
type TokenPurpose string

const (
	TokenPurposePasswordReset TokenPurpose = "password_reset"
	TokenPurposeMagicLink     TokenPurpose = "magic_link"
)

// Token represents a single-use, time-limited token for password resets or magic links.
type Token struct {
	ID        string
	UserID    string
	TokenHash string // SHA-256 hash of the raw token; raw token is never stored
	Purpose   TokenPurpose
	ExpiresAt time.Time
	CreatedAt time.Time
	Used      bool
}

// TokenStore defines the persistence operations for tokens.
type TokenStore interface {
	CreateToken(ctx context.Context, token *Token) error
	GetTokenByHash(ctx context.Context, hash string) (*Token, error)
	MarkTokenUsed(ctx context.Context, id string) error
	DeleteExpiredTokens(ctx context.Context) error
}

// generateRawToken creates a cryptographically random token and returns both
// the raw token (to send to the user) and its SHA-256 hash (to store).
func generateRawToken(nBytes int) (raw string, hash string, err error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b)
	return raw, hashToken(raw), nil
}

// hashToken computes the SHA-256 hash of a raw token string.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
