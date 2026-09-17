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
	// It also returns how many unused codes the user has left AFTER this
	// consumption, produced by the same atomic operation. Counting
	// afterwards, in a second call, reports whatever the store holds by
	// then, which under concurrent consumption includes somebody else's
	// deletion and not necessarily this one. A caller that shows the number
	// to a user, or that decides on it whether the last code is gone, needs
	// the count this operation produced, not a later one.
	//
	// Reference SQL: the delete's affected-row count does the lookup's job,
	// and the remaining count is read under the same serialization.
	//
	//	DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2
	//	SELECT count(*) FROM recovery_codes WHERE user_id = $1
	//
	// Zero rows affected is ErrCodeNotFound — spent, never issued, or
	// issued to somebody else. user_id belongs in the predicate rather than
	// in a check afterwards, so another user's code hash matches no row at
	// all rather than matching and then being rejected.
	//
	// The two statements MUST be serialized against other consumptions for
	// the same user, or the count is the stale one this signature exists to
	// avoid: two callers deleting two different codes of a three-code user
	// can both read two remaining. A mutex-guarded in-memory store holds one
	// lock across both. A SQL store needs a transaction plus whatever its
	// engine requires to make that transaction serial per user; snapshot
	// isolation alone is not enough, because a count is a question about
	// absent rows. Return 0 with the error when the code is not found.
	ConsumeCode(ctx context.Context, userID, hash string) (remaining int, err error)
	// CountCodes returns the number of unused codes remaining for the user.
	CountCodes(ctx context.Context, userID string) (int, error)
	// DeleteCodes removes all codes for the user.
	DeleteCodes(ctx context.Context, userID string) error
}
