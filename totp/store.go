package totp

import (
	"context"
	"time"
)

// Credential represents a user's TOTP enrollment.
type Credential struct {
	ID              string
	UserID          string
	Secret          string // base32-encoded shared secret
	Verified        bool   // true after the user confirms enrollment with a valid code
	LastUsedCounter uint64 // time-step counter of the last accepted code, for replay protection
	CreatedAt       time.Time
}

// Store defines the persistence operations for TOTP credentials.
type Store interface {
	// SaveTOTP creates or updates a TOTP credential. Implementations should
	// persist LastUsedCounter atomically with respect to concurrent
	// validates, so that two racing calls cannot both accept the same
	// (or an older) time-step counter.
	SaveTOTP(ctx context.Context, cred *Credential) error
	GetTOTPByUserID(ctx context.Context, userID string) (*Credential, error)
	DeleteTOTP(ctx context.Context, userID string) error
}
