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
	// SaveTOTP creates or updates a TOTP credential. Implementations MUST
	// persist LastUsedCounter atomically with respect to concurrent
	// validates, and MUST reject (fail closed) any save that would lower
	// LastUsedCounter for an existing credential with the same ID, so two
	// racing validates cannot both win. Re-enrollment is unaffected: Enroll
	// always generates a new credential ID, so a re-enrollment save never
	// collides with the prior credential's counter.
	SaveTOTP(ctx context.Context, cred *Credential) error
	GetTOTPByUserID(ctx context.Context, userID string) (*Credential, error)
	DeleteTOTP(ctx context.Context, userID string) error
}
