package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/borfast/sulis/recovery"
)

// RunRecoveryStore checks an implementation of recovery.Store against the
// contract documented on that interface.
//
// ConsumeCode must find and delete the matching code in one operation. A
// recovery code is a single-use bypass of every other factor, so a store that
// looks the code up and then deletes it lets two concurrent presentations of
// the same code both succeed — one code, two authentications. The suite races
// that directly, and pins the user scoping: a code is only ever valid for the
// user it was generated for.
//
// Only hashes are ever stored; the suite passes hashes throughout, as sulis
// does.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunRecoveryStore(t *testing.T, factory func() recovery.Store) {
	t.Helper()

	ctx := context.Background()

	t.Run("ReplaceCodesStoresTheWholeSet", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		hashes := newCodeHashes(5)
		if err := store.ReplaceCodes(ctx, userID, hashes); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}

		count, err := store.CountCodes(ctx, userID)
		if err != nil {
			t.Fatalf("CountCodes: %v", err)
		}
		if count != len(hashes) {
			t.Fatalf("CountCodes = %d, want %d", count, len(hashes))
		}
		for _, hash := range hashes {
			if err := store.ConsumeCode(ctx, userID, hash); err != nil {
				t.Fatalf("ConsumeCode(%q): %v", hash, err)
			}
		}
	})

	t.Run("ReplaceCodesDiscardsThePreviousSet", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		old := newCodeHashes(3)
		if err := store.ReplaceCodes(ctx, userID, old); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}
		fresh := newCodeHashes(4)
		if err := store.ReplaceCodes(ctx, userID, fresh); err != nil {
			t.Fatalf("second ReplaceCodes: %v", err)
		}

		count, err := store.CountCodes(ctx, userID)
		if err != nil {
			t.Fatalf("CountCodes: %v", err)
		}
		if count != len(fresh) {
			t.Fatalf("CountCodes = %d, want %d — regenerating must replace the set, not add to it", count, len(fresh))
		}
		// Codes from the discarded set must no longer authenticate anyone.
		if err := store.ConsumeCode(ctx, userID, old[0]); !errors.Is(err, recovery.ErrCodeNotFound) {
			t.Fatalf("ConsumeCode with a superseded code error = %v, want ErrCodeNotFound", err)
		}
	})

	t.Run("ConsumeCodeRemovesOnlyThatCode", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		hashes := newCodeHashes(3)
		if err := store.ReplaceCodes(ctx, userID, hashes); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}

		if err := store.ConsumeCode(ctx, userID, hashes[1]); err != nil {
			t.Fatalf("ConsumeCode: %v", err)
		}
		count, err := store.CountCodes(ctx, userID)
		if err != nil {
			t.Fatalf("CountCodes: %v", err)
		}
		if count != len(hashes)-1 {
			t.Fatalf("CountCodes = %d, want %d", count, len(hashes)-1)
		}
		for _, hash := range []string{hashes[0], hashes[2]} {
			if err := store.ConsumeCode(ctx, userID, hash); err != nil {
				t.Fatalf("a sibling code was consumed too: ConsumeCode(%q) = %v", hash, err)
			}
		}
	})

	t.Run("ConsumeCodeTwiceReturnsErrCodeNotFound", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		hashes := newCodeHashes(2)
		if err := store.ReplaceCodes(ctx, userID, hashes); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}
		if err := store.ConsumeCode(ctx, userID, hashes[0]); err != nil {
			t.Fatalf("first ConsumeCode: %v", err)
		}

		if err := store.ConsumeCode(ctx, userID, hashes[0]); !errors.Is(err, recovery.ErrCodeNotFound) {
			t.Fatalf("second ConsumeCode error = %v, want ErrCodeNotFound — a recovery code is single-use", err)
		}
	})

	t.Run("ConsumeCodeForAnotherUserReturnsErrCodeNotFound", func(t *testing.T) {
		store := factory()
		ownerID := uniqueID("owner")
		hashes := newCodeHashes(2)
		if err := store.ReplaceCodes(ctx, ownerID, hashes); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}

		attackerID := uniqueID("attacker")
		if err := store.ConsumeCode(ctx, attackerID, hashes[0]); !errors.Is(err, recovery.ErrCodeNotFound) {
			t.Fatalf("cross-user ConsumeCode error = %v, want ErrCodeNotFound", err)
		}
		// And the owner's code must still be there to use.
		if err := store.ConsumeCode(ctx, ownerID, hashes[0]); err != nil {
			t.Fatalf("the owner's code was consumed by another user's attempt: %v", err)
		}
	})

	t.Run("ConsumeCodeUnknownHashReturnsErrCodeNotFound", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		if err := store.ReplaceCodes(ctx, userID, newCodeHashes(2)); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}
		if err := store.ConsumeCode(ctx, userID, uniqueHash("absent")); !errors.Is(err, recovery.ErrCodeNotFound) {
			t.Fatalf("ConsumeCode with an unknown hash error = %v, want ErrCodeNotFound", err)
		}
	})

	t.Run("CountCodesForAnUnknownUserReturnsZero", func(t *testing.T) {
		store := factory()
		count, err := store.CountCodes(ctx, uniqueID("user"))
		if err != nil {
			t.Fatalf("CountCodes for a user with no codes: %v — having none is not an error", err)
		}
		if count != 0 {
			t.Fatalf("CountCodes = %d, want 0", count)
		}
	})

	t.Run("DeleteCodesRemovesEveryCode", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		hashes := newCodeHashes(3)
		if err := store.ReplaceCodes(ctx, userID, hashes); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}

		if err := store.DeleteCodes(ctx, userID); err != nil {
			t.Fatalf("DeleteCodes: %v", err)
		}
		count, err := store.CountCodes(ctx, userID)
		if err != nil {
			t.Fatalf("CountCodes: %v", err)
		}
		if count != 0 {
			t.Fatalf("CountCodes = %d after DeleteCodes, want 0", count)
		}
		if err := store.ConsumeCode(ctx, userID, hashes[0]); !errors.Is(err, recovery.ErrCodeNotFound) {
			t.Fatalf("ConsumeCode after DeleteCodes error = %v, want ErrCodeNotFound", err)
		}
	})

	t.Run("ReplaceCodesWithAnEmptySetClearsTheCodes", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		if err := store.ReplaceCodes(ctx, userID, newCodeHashes(2)); err != nil {
			t.Fatalf("ReplaceCodes: %v", err)
		}
		if err := store.ReplaceCodes(ctx, userID, nil); err != nil {
			t.Fatalf("ReplaceCodes with an empty set: %v", err)
		}
		count, err := store.CountCodes(ctx, userID)
		if err != nil {
			t.Fatalf("CountCodes: %v", err)
		}
		if count != 0 {
			t.Fatalf("CountCodes = %d, want 0", count)
		}
	})

	t.Run("DeleteCodesForAnUnknownUserIsNotAnError", func(t *testing.T) {
		store := factory()
		if err := store.DeleteCodes(ctx, uniqueID("user")); err != nil {
			t.Fatalf("DeleteCodes with nothing to delete: %v", err)
		}
	})

	t.Run("ConcurrentConsumeCodeHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			hashes := newCodeHashes(2)
			if err := store.ReplaceCodes(ctx, userID, hashes); err != nil {
				t.Fatalf("iteration %d: ReplaceCodes: %v", i, err)
			}

			// One code, presented by everyone at once. A recovery code
			// bypasses every other factor, so a store that reads then deletes
			// turns one code into as many authentications as there are
			// callers.
			errs := race(racers, func(int) error {
				return store.ConsumeCode(ctx, userID, hashes[0])
			})
			exactlyOneWinner(t, errs, recovery.ErrCodeNotFound,
				fmt.Sprintf("iteration %d: concurrent ConsumeCode", i))

			count, err := store.CountCodes(ctx, userID)
			if err != nil {
				t.Fatalf("iteration %d: CountCodes: %v", i, err)
			}
			if count != len(hashes)-1 {
				t.Fatalf("iteration %d: CountCodes = %d, want %d — exactly one code was consumed",
					i, count, len(hashes)-1)
			}
		}
	})

	t.Run("ConcurrentConsumeOfDistinctCodesAllSucceed", func(t *testing.T) {
		const codes = 8

		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			hashes := newCodeHashes(codes)
			if err := store.ReplaceCodes(ctx, userID, hashes); err != nil {
				t.Fatalf("iteration %d: ReplaceCodes: %v", i, err)
			}

			// Distinct codes contend for nothing: a store that serializes them
			// too coarsely still has to let every one of them through.
			errs := race(codes, func(g int) error {
				return store.ConsumeCode(ctx, userID, hashes[g])
			})
			for g, err := range errs {
				if err != nil {
					t.Fatalf("iteration %d: ConsumeCode(%d) = %v, want nil", i, g, err)
				}
			}
			count, err := store.CountCodes(ctx, userID)
			if err != nil {
				t.Fatalf("iteration %d: CountCodes: %v", i, err)
			}
			if count != 0 {
				t.Fatalf("iteration %d: CountCodes = %d, want 0", i, count)
			}
		}
	})
}

// newCodeHashes returns n distinct code hashes in the shape sulis stores them
// (lowercase hex SHA-256). The plaintext codes never exist here, the same as
// in a real deployment after generation.
func newCodeHashes(n int) []string {
	hashes := make([]string, n)
	for i := range hashes {
		hashes[i] = uniqueHash("code")
	}
	return hashes
}
