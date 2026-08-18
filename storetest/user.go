package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/borfast/sulis"
)

// RunUserStore checks an implementation of sulis.UserStore against the
// contract documented on that interface.
//
// Two requirements carry the weight here, and both are invisible to the
// compiler.
//
// Version is optimistic concurrency: UpdateUser must apply the write only
// while the stored row's version still matches the one the caller read, and
// must return ErrConcurrentUpdate otherwise. Without it, two flows that each
// read-modify-write the whole user row silently clobber each other, and the
// dangerous direction restores a password hash the user just rotated away
// from.
//
// Email uniqueness must be enforced by the store's write path, on CreateUser
// and on UpdateUser alike. Version guards one row against a lost update; it
// says nothing about two different rows racing to claim the same address, and
// nothing above the interface can make those writes atomic with respect to
// each other. The concurrency subtests below race both paths, since a store
// that only rejects duplicates it happens to notice on a prior read passes
// the sequential checks and fails these.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunUserStore(t *testing.T, factory func() sulis.UserStore) {
	t.Helper()

	ctx := context.Background()

	t.Run("CreateUserRoundTrips", func(t *testing.T) {
		store := factory()
		u := newUser()
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		byID, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		assertUserMatches(t, "GetUserByID", byID, u)

		byEmail, err := store.GetUserByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("GetUserByEmail: %v", err)
		}
		assertUserMatches(t, "GetUserByEmail", byEmail, u)
	})

	t.Run("GetUserByIDUnknownReturnsErrUserNotFound", func(t *testing.T) {
		store := factory()
		if _, err := store.GetUserByID(ctx, uniqueID("absent")); !errors.Is(err, sulis.ErrUserNotFound) {
			t.Fatalf("GetUserByID error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("GetUserByEmailUnknownReturnsErrUserNotFound", func(t *testing.T) {
		store := factory()
		if _, err := store.GetUserByEmail(ctx, uniqueEmail("absent")); !errors.Is(err, sulis.ErrUserNotFound) {
			t.Fatalf("GetUserByEmail error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("CreateUserDuplicateEmailReturnsErrUserAlreadyExists", func(t *testing.T) {
		store := factory()
		first := newUser()
		if err := store.CreateUser(ctx, first); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		second := newUser()
		second.Email = first.Email
		if err := store.CreateUser(ctx, second); !errors.Is(err, sulis.ErrUserAlreadyExists) {
			t.Fatalf("CreateUser with a duplicate email error = %v, want ErrUserAlreadyExists", err)
		}
		// The rejected create must not have displaced the original row.
		got, err := store.GetUserByEmail(ctx, first.Email)
		if err != nil {
			t.Fatalf("GetUserByEmail after a rejected create: %v", err)
		}
		if got.ID != first.ID {
			t.Fatalf("email %q now belongs to %q, want %q", first.Email, got.ID, first.ID)
		}
	})

	t.Run("UpdateUserPersistsAndAdvancesVersion", func(t *testing.T) {
		store := factory()
		u := newUser()
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		read, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}

		read.PasswordHash = "rotated"
		if err := store.UpdateUser(ctx, read); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}

		after, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID after update: %v", err)
		}
		if after.PasswordHash != "rotated" {
			t.Errorf("PasswordHash = %q, want %q", after.PasswordHash, "rotated")
		}
		if after.Version <= read.Version {
			t.Errorf("Version = %d after updating from version %d, want it to advance — a version that does not move cannot detect a stale write",
				after.Version, read.Version)
		}
	})

	t.Run("UpdateUserWithStaleVersionReturnsErrConcurrentUpdate", func(t *testing.T) {
		store := factory()
		u := newUser()
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		// Two flows read the same row, then both try to write it.
		first, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		second, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}

		first.PasswordHash = "winner"
		if err := store.UpdateUser(ctx, first); err != nil {
			t.Fatalf("first UpdateUser: %v", err)
		}

		second.PasswordHash = "loser"
		if err := store.UpdateUser(ctx, second); !errors.Is(err, sulis.ErrConcurrentUpdate) {
			t.Fatalf("stale UpdateUser error = %v, want ErrConcurrentUpdate", err)
		}

		after, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID after the rejected update: %v", err)
		}
		if after.PasswordHash != "winner" {
			t.Fatalf("PasswordHash = %q, want %q — the rejected write must be discarded, not applied",
				after.PasswordHash, "winner")
		}
	})

	t.Run("UpdateUserRejectsAnotherUsersEmail", func(t *testing.T) {
		store := factory()
		occupant := newUser()
		mover := newUser()
		for _, u := range []*sulis.User{occupant, mover} {
			if err := store.CreateUser(ctx, u); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
		}

		read, err := store.GetUserByID(ctx, mover.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		read.Email = occupant.Email
		if err := store.UpdateUser(ctx, read); !errors.Is(err, sulis.ErrUserAlreadyExists) {
			t.Fatalf("UpdateUser onto another user's email error = %v, want ErrUserAlreadyExists", err)
		}

		// Neither row may have moved.
		stillOccupant, err := store.GetUserByEmail(ctx, occupant.Email)
		if err != nil {
			t.Fatalf("GetUserByEmail: %v", err)
		}
		if stillOccupant.ID != occupant.ID {
			t.Fatalf("email %q now belongs to %q, want %q", occupant.Email, stillOccupant.ID, occupant.ID)
		}
		stillMover, err := store.GetUserByID(ctx, mover.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if stillMover.Email != mover.Email {
			t.Fatalf("Email = %q, want the unchanged %q", stillMover.Email, mover.Email)
		}
	})

	t.Run("UpdateUserKeepingItsOwnEmailIsNotACollision", func(t *testing.T) {
		store := factory()
		u := newUser()
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		read, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}

		// The uniqueness check must exclude the row being written, or every
		// update that touches anything else would fail.
		read.PendingEmail = uniqueEmail("staged")
		if err := store.UpdateUser(ctx, read); err != nil {
			t.Fatalf("UpdateUser keeping its own email: %v", err)
		}
	})

	t.Run("UpdateUserForAnUnknownIDFails", func(t *testing.T) {
		store := factory()
		u := newUser()
		// Never created: a write that matches no row must report that rather
		// than conjuring one or reporting success.
		if err := store.UpdateUser(ctx, u); err == nil {
			t.Fatal("UpdateUser for an unknown user returned nil, want an error")
		}
	})

	t.Run("DeleteUserRemovesTheUser", func(t *testing.T) {
		store := factory()
		u := newUser()
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := store.DeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if _, err := store.GetUserByID(ctx, u.ID); !errors.Is(err, sulis.ErrUserNotFound) {
			t.Fatalf("GetUserByID after delete = %v, want ErrUserNotFound", err)
		}
		if _, err := store.GetUserByEmail(ctx, u.Email); !errors.Is(err, sulis.ErrUserNotFound) {
			t.Fatalf("GetUserByEmail after delete = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("ReturnedUsersAreIndependentOfStoredState", func(t *testing.T) {
		store := factory()
		u := newUser()
		u.Metadata = map[string]any{"role": "member"}
		verifiedAt := time.Now().UTC().Truncate(time.Second)
		u.EmailVerifiedAt = &verifiedAt
		wantHash, wantEmail := u.PasswordHash, u.Email
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		// A caller that mutates what it read must not have mutated the store:
		// the whole point of Version is that a change only lands through
		// UpdateUser.
		read, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		read.PasswordHash = "not persisted"
		read.Email = uniqueEmail("not-persisted")
		// A struct copy copies a map header, not the map, and a pointer, not
		// what it points at. Both leave the caller holding a live handle on
		// the stored row.
		mutateMetadata(read.Metadata)
		if read.EmailVerifiedAt != nil {
			*read.EmailVerifiedAt = time.Unix(0, 0).UTC()
		}

		after, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if after.PasswordHash != wantHash || after.Email != wantEmail {
			t.Fatalf("mutating the value returned by GetUserByID changed stored state (hash %q, email %q)",
				after.PasswordHash, after.Email)
		}
		assertMetadataUnchanged(t, "GetUserByID", after.Metadata, "role", "member")
		if after.EmailVerifiedAt != nil && after.EmailVerifiedAt.Equal(time.Unix(0, 0).UTC()) {
			t.Fatal("mutating *EmailVerifiedAt on the value returned by GetUserByID changed stored state — the pointer must not be shared with the store")
		}

		// The same must hold for the value handed to CreateUser.
		u.PasswordHash = "also not persisted"
		mutateMetadata(u.Metadata)
		*u.EmailVerifiedAt = time.Unix(0, 0).UTC()

		final, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if final.PasswordHash != wantHash {
			t.Fatalf("mutating the *User passed to CreateUser changed stored state (hash %q)", final.PasswordHash)
		}
		assertMetadataUnchanged(t, "CreateUser", final.Metadata, "role", "member")
		if final.EmailVerifiedAt != nil && final.EmailVerifiedAt.Equal(time.Unix(0, 0).UTC()) {
			t.Fatal("mutating *EmailVerifiedAt on the *User passed to CreateUser changed stored state")
		}

		// And for the value handed to UpdateUser, the other write path.
		toUpdate, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		toUpdate.Metadata = map[string]any{"role": "admin"}
		if err := store.UpdateUser(ctx, toUpdate); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		mutateMetadata(toUpdate.Metadata)

		updated, err := store.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		assertMetadataUnchanged(t, "UpdateUser", updated.Metadata, "role", "admin")
	})

	t.Run("ConcurrentUpdateUserFromOneReadHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			u := newUser()
			if err := store.CreateUser(ctx, u); err != nil {
				t.Fatalf("iteration %d: CreateUser: %v", i, err)
			}
			snapshot, err := store.GetUserByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("iteration %d: GetUserByID: %v", i, err)
			}

			// Every racer writes the same version it read, so at most one can
			// be applied. A store that ignores Version applies all of them
			// and the last writer silently wins.
			errs := race(racers, func(g int) error {
				write := *snapshot
				write.PasswordHash = fmt.Sprintf("hash-from-%d", g)
				return store.UpdateUser(ctx, &write)
			})
			winner := exactlyOneWinner(t, errs, sulis.ErrConcurrentUpdate,
				fmt.Sprintf("iteration %d: concurrent UpdateUser", i))

			after, err := store.GetUserByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("iteration %d: GetUserByID: %v", i, err)
			}
			want := fmt.Sprintf("hash-from-%d", winner)
			if after.PasswordHash != want {
				t.Fatalf("iteration %d: stored PasswordHash = %q, want %q from the only writer that succeeded",
					i, after.PasswordHash, want)
			}
			if after.Version <= snapshot.Version {
				t.Fatalf("iteration %d: Version = %d, want it past the %d every racer wrote against",
					i, after.Version, snapshot.Version)
			}
		}
	})

	t.Run("ConcurrentCreateUserWithOneEmailHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			email := uniqueEmail("contested")

			ids := make([]string, racers)
			errs := race(racers, func(g int) error {
				u := newUser()
				u.Email = email
				ids[g] = u.ID
				return store.CreateUser(ctx, u)
			})
			winner := exactlyOneWinner(t, errs, sulis.ErrUserAlreadyExists,
				fmt.Sprintf("iteration %d: concurrent CreateUser for one email", i))

			got, err := store.GetUserByEmail(ctx, email)
			if err != nil {
				t.Fatalf("iteration %d: GetUserByEmail: %v", i, err)
			}
			if got.ID != ids[winner] {
				t.Fatalf("iteration %d: email %q belongs to %q, want the only successful creator %q",
					i, email, got.ID, ids[winner])
			}
		}
	})

	t.Run("ConcurrentUpdateUserOntoOneEmailHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			target := uniqueEmail("contested")

			// Distinct rows, each read before the race, all trying to claim
			// the same free address — two accounts confirming a staged change
			// to the same address, which is exactly the case Version cannot
			// help with, since the writes touch different rows.
			reads := make([]*sulis.User, racers)
			for g := range racers {
				u := newUser()
				if err := store.CreateUser(ctx, u); err != nil {
					t.Fatalf("iteration %d: CreateUser: %v", i, err)
				}
				read, err := store.GetUserByID(ctx, u.ID)
				if err != nil {
					t.Fatalf("iteration %d: GetUserByID: %v", i, err)
				}
				reads[g] = read
			}

			errs := race(racers, func(g int) error {
				write := *reads[g]
				write.Email = target
				write.PendingEmail = ""
				return store.UpdateUser(ctx, &write)
			})
			winner := exactlyOneWinner(t, errs, sulis.ErrUserAlreadyExists,
				fmt.Sprintf("iteration %d: concurrent UpdateUser onto one email", i))

			got, err := store.GetUserByEmail(ctx, target)
			if err != nil {
				t.Fatalf("iteration %d: GetUserByEmail: %v", i, err)
			}
			if got.ID != reads[winner].ID {
				t.Fatalf("iteration %d: email %q belongs to %q, want the only successful writer %q",
					i, target, got.ID, reads[winner].ID)
			}
			// Every loser must still hold its original address.
			for g, read := range reads {
				if g == winner {
					continue
				}
				after, err := store.GetUserByID(ctx, read.ID)
				if err != nil {
					t.Fatalf("iteration %d: GetUserByID: %v", i, err)
				}
				if after.Email != read.Email {
					t.Fatalf("iteration %d: rejected writer %q now has email %q, want the unchanged %q",
						i, read.ID, after.Email, read.Email)
				}
			}
		}
	})
}

// newUser builds a user with unique identifiers and every field a store might
// persist set to something distinguishable.
func newUser() *sulis.User {
	now := time.Now().UTC().Truncate(time.Second)
	return &sulis.User{
		ID:           uniqueID("user"),
		Email:        uniqueEmail("user"),
		PasswordHash: "argon2id$placeholder$" + uniqueID("hash"),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// assertUserMatches compares the fields the UserStore contract requires a
// store to round-trip. Timestamps are deliberately excluded: databases
// legitimately differ on the precision and location they store them in, and
// the interface promises nothing about either.
func assertUserMatches(t *testing.T, op string, got, want *sulis.User) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s returned a nil user and a nil error", op)
	}
	if got.ID != want.ID {
		t.Errorf("%s: ID = %q, want %q", op, got.ID, want.ID)
	}
	if got.Email != want.Email {
		t.Errorf("%s: Email = %q, want %q", op, got.Email, want.Email)
	}
	if got.PasswordHash != want.PasswordHash {
		t.Errorf("%s: PasswordHash = %q, want %q", op, got.PasswordHash, want.PasswordHash)
	}
	if got.PendingEmail != want.PendingEmail {
		t.Errorf("%s: PendingEmail = %q, want %q", op, got.PendingEmail, want.PendingEmail)
	}
}
