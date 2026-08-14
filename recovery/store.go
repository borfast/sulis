package recovery

import (
	"context"
	"errors"
)

// ErrCodeNotFound is returned by Store implementations when ConsumeCode
// finds no matching, unused code for the given user.
var ErrCodeNotFound = errors.New("recovery: code not found")

// Store defines the persistence operations for recovery codes.
//
// Recovery codes are persisted as hashes only; the plaintext codes are
// never stored.
type Store interface {
	// ReplaceCodes atomically replaces the user's full code set.
	ReplaceCodes(ctx context.Context, userID string, hashes []string) error
	// ConsumeCode atomically deletes the code matching userID+hash.
	// Returns ErrCodeNotFound if absent. Lookup and delete MUST be atomic.
	ConsumeCode(ctx context.Context, userID, hash string) error
	// CountCodes returns the number of unused codes remaining for the user.
	CountCodes(ctx context.Context, userID string) (int, error)
	// DeleteCodes removes all codes for the user.
	DeleteCodes(ctx context.Context, userID string) error
}
