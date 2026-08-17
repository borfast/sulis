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
	TokenPurposePasswordReset     TokenPurpose = "password_reset"
	TokenPurposeMagicLink         TokenPurpose = "magic_link"
	TokenPurposeTwoFactor         TokenPurpose = "two_factor"
	TokenPurposeEmailVerification TokenPurpose = "email_verification" // #nosec G101 -- a purpose label, not a credential
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
	// Email records the address a token proves control of. It is set for
	// magic-link tokens issued before the user account exists (UserID is
	// empty in that case until the token is redeemed) and for
	// email-verification tokens (bound to the user's email at issuance, so a
	// later address change invalidates an outstanding token). It is empty
	// for password-reset and two-factor tokens.
	Email string
}

// TokenStore defines the persistence operations for tokens.
type TokenStore interface {
	CreateToken(ctx context.Context, token *Token) error
	// ConsumeToken atomically finds the unused token matching hash AND purpose
	// and marks it used, returning it. Lookup and mark MUST be one atomic
	// operation (e.g. UPDATE ... WHERE hash=? AND purpose=? AND used=false).
	// Returns ErrTokenNotFound if no token matches hash+purpose;
	// ErrTokenAlreadyUsed if it exists but was already consumed.
	ConsumeToken(ctx context.Context, hash string, purpose TokenPurpose) (*Token, error)
	DeleteExpiredTokens(ctx context.Context) error
	// DeleteUserTokens deletes all tokens for the given user and purpose.
	// Deleting zero tokens is not an error.
	DeleteUserTokens(ctx context.Context, userID string, purpose TokenPurpose) error
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
