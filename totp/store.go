package totp

import (
	"context"
	"time"
)

// Credential represents a user's TOTP enrollment.
type Credential struct {
	ID        string
	UserID    string
	Secret    string // base32-encoded shared secret
	Verified  bool   // true after the user confirms enrollment with a valid code
	CreatedAt time.Time
}

// Store defines the persistence operations for TOTP credentials.
type Store interface {
	SaveTOTP(ctx context.Context, cred *Credential) error
	GetTOTPByUserID(ctx context.Context, userID string) (*Credential, error)
	DeleteTOTP(ctx context.Context, userID string) error
}
