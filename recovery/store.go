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
	// Returns ErrCodeNotFound if absent. Lookup and delete MUST be one
	// atomic operation — the same requirement TokenStore.ConsumeToken,
	// passkey.ChallengeStore.ConsumeChallenge, and
	// passkey.Store.DeleteCredential place on their own check-and-mutate
	// operations, and here for the sharpest version of the reason: a
	// recovery code is a single-use bypass of every other factor, so a
	// store that reads the row and then deletes it lets two concurrent
	// presentations of the same code both succeed. That is one code and two
	// authentications, and the second one belongs to whoever else has the
	// printed list.
	//
	// Reference SQL: one statement, with the affected-row count doing the
	// lookup's job.
	//
	//	DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2
	//
	// Zero rows affected is ErrCodeNotFound — spent, never issued, or
	// issued to somebody else. user_id belongs in the predicate rather than
	// in a check afterwards, so another user's code hash matches no row at
	// all rather than matching and then being rejected. A single-threaded
	// or mutex-guarded in-memory store can simply perform the lookup and
	// the delete while holding the same lock.
	ConsumeCode(ctx context.Context, userID, hash string) error
	// CountCodes returns the number of unused codes remaining for the user.
	CountCodes(ctx context.Context, userID string) (int, error)
	// DeleteCodes removes all codes for the user.
	DeleteCodes(ctx context.Context, userID string) error
}
