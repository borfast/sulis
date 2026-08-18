package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/borfast/sulis/totp"
)

// RunTOTPStore checks an implementation of totp.Store against the contract
// documented on that interface.
//
// Three requirements carry the weight, and all three are invisible to the
// compiler.
//
// The pending and active slots must stay separate — at most one of each per
// user — so a stray or racing enrollment can never silently replace an
// already-verified factor. EnrollPending must refuse when an active
// credential exists, and it must make that check and its write one operation.
//
// ConfirmEnrollment is a compare-and-swap: it promotes the pending enrollment
// only while it is still the exact one identified by pendingID. Without that,
// a racing EnrollPending in the gap between Service reading the pending
// enrollment and the store committing the promotion would either promote a
// secret nobody validated a code against, or silently discard a fresh
// enrollment, with neither caller finding out.
//
// The replay counter must never move backwards. SaveTOTP must reject a save
// that would lower LastUsedCounter for the active credential with the same
// ID, and a ConfirmEnrollment that replaces an existing factor must carry the
// old counter forward when it is the higher of the two. A counter that can
// regress is a code that can be replayed.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunTOTPStore(t *testing.T, factory func() totp.Store) {
	t.Helper()

	ctx := context.Background()

	t.Run("EnrollPendingFillsOnlyThePendingSlot", func(t *testing.T) {
		store := factory()
		cred := newTOTPCredential(uniqueID("user"))
		if err := store.EnrollPending(ctx, cred); err != nil {
			t.Fatalf("EnrollPending: %v", err)
		}

		pending, err := store.GetPendingTOTP(ctx, cred.UserID)
		if err != nil {
			t.Fatalf("GetPendingTOTP: %v", err)
		}
		if pending.ID != cred.ID || pending.Secret != cred.Secret {
			t.Fatalf("GetPendingTOTP = %+v, want the enrolled %+v", pending, cred)
		}
		if pending.Verified {
			t.Error("GetPendingTOTP returned Verified = true; a pending enrollment is by definition unverified")
		}
		if _, err := store.GetActiveTOTP(ctx, cred.UserID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetActiveTOTP error = %v, want ErrTOTPNotEnrolled: a pending enrollment is not an active factor", err)
		}
	})

	t.Run("GetPendingTOTPWithNoneReturnsErrTOTPNotEnrolled", func(t *testing.T) {
		store := factory()
		if _, err := store.GetPendingTOTP(ctx, uniqueID("user")); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetPendingTOTP error = %v, want ErrTOTPNotEnrolled", err)
		}
	})

	t.Run("GetActiveTOTPWithNoneReturnsErrTOTPNotEnrolled", func(t *testing.T) {
		store := factory()
		if _, err := store.GetActiveTOTP(ctx, uniqueID("user")); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetActiveTOTP error = %v, want ErrTOTPNotEnrolled", err)
		}
	})

	t.Run("EnrollPendingSupersedesAnEarlierPendingEnrollment", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		first := newTOTPCredential(userID)
		if err := store.EnrollPending(ctx, first); err != nil {
			t.Fatalf("EnrollPending: %v", err)
		}
		second := newTOTPCredential(userID)
		if err := store.EnrollPending(ctx, second); err != nil {
			t.Fatalf("second EnrollPending: %v", err)
		}

		// At most one pending enrollment per user, and an unconfirmed one has
		// nothing worth protecting.
		pending, err := store.GetPendingTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetPendingTOTP: %v", err)
		}
		if pending.ID != second.ID {
			t.Fatalf("GetPendingTOTP = %q, want the most recent enrollment %q", pending.ID, second.ID)
		}
	})

	t.Run("ConfirmEnrollmentPromotesThePendingEnrollment", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		cred := newTOTPCredential(userID)
		if err := store.EnrollPending(ctx, cred); err != nil {
			t.Fatalf("EnrollPending: %v", err)
		}

		promoted, err := store.ConfirmEnrollment(ctx, userID, cred.ID, 42)
		if err != nil {
			t.Fatalf("ConfirmEnrollment: %v", err)
		}
		if promoted == nil {
			t.Fatal("ConfirmEnrollment returned a nil credential and a nil error")
		}
		if promoted.ID != cred.ID || promoted.Secret != cred.Secret {
			t.Fatalf("ConfirmEnrollment returned %+v, want the pending %+v", promoted, cred)
		}
		if !promoted.Verified {
			t.Error("ConfirmEnrollment returned Verified = false; promotion is what makes a credential verified")
		}

		active, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if active.ID != cred.ID || active.Secret != cred.Secret {
			t.Fatalf("GetActiveTOTP = %+v, want the promoted %+v", active, cred)
		}
		if !active.Verified {
			t.Error("GetActiveTOTP returned Verified = false; every active credential is verified")
		}
		if active.LastUsedCounter != 42 {
			t.Errorf("LastUsedCounter = %d, want the 42 the code was matched at — the confirming code must not be replayable",
				active.LastUsedCounter)
		}
		if _, err := store.GetPendingTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetPendingTOTP after promotion = %v, want ErrTOTPNotEnrolled: the pending slot must be emptied", err)
		}
	})

	t.Run("ConfirmEnrollmentWithAStalePendingIDReturnsErrTOTPNotEnrolled", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		stale := newTOTPCredential(userID)
		if err := store.EnrollPending(ctx, stale); err != nil {
			t.Fatalf("EnrollPending: %v", err)
		}
		current := newTOTPCredential(userID)
		if err := store.EnrollPending(ctx, current); err != nil {
			t.Fatalf("second EnrollPending: %v", err)
		}

		// The caller validated a code against the superseded enrollment, so
		// promoting anything would promote a secret nobody proved control of.
		if _, err := store.ConfirmEnrollment(ctx, userID, stale.ID, 1); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("ConfirmEnrollment with a stale pendingID error = %v, want ErrTOTPNotEnrolled", err)
		}
		if _, err := store.GetActiveTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetActiveTOTP = %v, want ErrTOTPNotEnrolled: a refused confirmation must promote nothing", err)
		}
		pending, err := store.GetPendingTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetPendingTOTP: %v", err)
		}
		if pending.ID != current.ID {
			t.Fatalf("GetPendingTOTP = %q, want the untouched %q", pending.ID, current.ID)
		}
	})

	t.Run("ConfirmEnrollmentRepeatedAfterSuccessReturnsErrTOTPNotEnrolled", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		cred := newTOTPCredential(userID)
		if err := store.EnrollPending(ctx, cred); err != nil {
			t.Fatalf("EnrollPending: %v", err)
		}
		if _, err := store.ConfirmEnrollment(ctx, userID, cred.ID, 7); err != nil {
			t.Fatalf("ConfirmEnrollment: %v", err)
		}

		// Nothing left to confirm — and crucially, the active credential must
		// not be disturbed by the retry.
		if _, err := store.ConfirmEnrollment(ctx, userID, cred.ID, 8); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("repeated ConfirmEnrollment error = %v, want ErrTOTPNotEnrolled", err)
		}
		active, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if active.ID != cred.ID || active.LastUsedCounter != 7 {
			t.Fatalf("active credential = %+v, want %q at counter 7 — the refused retry must change nothing", active, cred.ID)
		}
	})

	t.Run("EnrollPendingRefusesWhenAnActiveCredentialExists", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		active := enrollAndConfirm(t, store, userID, 5)

		if err := store.EnrollPending(ctx, newTOTPCredential(userID)); !errors.Is(err, totp.ErrTOTPAlreadyEnrolled) {
			t.Fatalf("EnrollPending over an active credential error = %v, want ErrTOTPAlreadyEnrolled", err)
		}
		// The working second factor must be exactly as it was.
		got, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if got.ID != active.ID || got.Secret != active.Secret {
			t.Fatalf("active credential = %+v, want the untouched %+v", got, active)
		}
	})

	t.Run("ReplacePendingLeavesTheActiveCredentialUntouched", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		active := enrollAndConfirm(t, store, userID, 5)

		replacement := newTOTPCredential(userID)
		if err := store.ReplacePending(ctx, replacement); err != nil {
			t.Fatalf("ReplacePending: %v", err)
		}

		// Validate must keep checking codes against the old factor until a
		// later ConfirmEnrollment promotes the replacement.
		got, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if got.ID != active.ID || got.Secret != active.Secret {
			t.Fatalf("active credential = %+v, want the untouched %+v", got, active)
		}
		pending, err := store.GetPendingTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetPendingTOTP: %v", err)
		}
		if pending.ID != replacement.ID {
			t.Fatalf("GetPendingTOTP = %q, want %q", pending.ID, replacement.ID)
		}
	})

	t.Run("ConfirmEnrollmentCarriesTheOldCounterForward", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		enrollAndConfirm(t, store, userID, 100)

		// Replacing a factor must never roll the replay clock backwards, even
		// though the promoted credential has a different secret.
		replacement := newTOTPCredential(userID)
		if err := store.ReplacePending(ctx, replacement); err != nil {
			t.Fatalf("ReplacePending: %v", err)
		}
		promoted, err := store.ConfirmEnrollment(ctx, userID, replacement.ID, 40)
		if err != nil {
			t.Fatalf("ConfirmEnrollment: %v", err)
		}
		if promoted.LastUsedCounter != 100 {
			t.Fatalf("LastUsedCounter = %d, want the higher prior 100 — a factor swap must not roll the replay clock back",
				promoted.LastUsedCounter)
		}
		active, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if active.LastUsedCounter != 100 {
			t.Fatalf("stored LastUsedCounter = %d, want 100", active.LastUsedCounter)
		}
	})

	t.Run("ConfirmEnrollmentTakesTheHigherOfTheTwoCounters", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		enrollAndConfirm(t, store, userID, 10)

		replacement := newTOTPCredential(userID)
		if err := store.ReplacePending(ctx, replacement); err != nil {
			t.Fatalf("ReplacePending: %v", err)
		}
		promoted, err := store.ConfirmEnrollment(ctx, userID, replacement.ID, 500)
		if err != nil {
			t.Fatalf("ConfirmEnrollment: %v", err)
		}
		if promoted.LastUsedCounter != 500 {
			t.Fatalf("LastUsedCounter = %d, want the higher new 500", promoted.LastUsedCounter)
		}
	})

	t.Run("SaveTOTPPersistsAnAdvancedCounter", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		active := enrollAndConfirm(t, store, userID, 10)

		active.LastUsedCounter = 11
		if err := store.SaveTOTP(ctx, active); err != nil {
			t.Fatalf("SaveTOTP: %v", err)
		}
		got, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if got.LastUsedCounter != 11 {
			t.Fatalf("LastUsedCounter = %d, want 11", got.LastUsedCounter)
		}
	})

	t.Run("SaveTOTPRejectsALoweredCounter", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		active := enrollAndConfirm(t, store, userID, 10)

		lowered := *active
		lowered.LastUsedCounter = 9
		if err := store.SaveTOTP(ctx, &lowered); err == nil {
			t.Fatal("SaveTOTP with a lowered counter returned nil, want an error: a counter that can regress is a code that can be replayed")
		}
		got, err := store.GetActiveTOTP(ctx, userID)
		if err != nil {
			t.Fatalf("GetActiveTOTP: %v", err)
		}
		if got.LastUsedCounter != 10 {
			t.Fatalf("LastUsedCounter = %d, want the unchanged 10 — a rejected save must not be applied", got.LastUsedCounter)
		}
	})

	t.Run("DeleteTOTPRemovesBothSlots", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		enrollAndConfirm(t, store, userID, 3)
		if err := store.ReplacePending(ctx, newTOTPCredential(userID)); err != nil {
			t.Fatalf("ReplacePending: %v", err)
		}

		if err := store.DeleteTOTP(ctx, userID); err != nil {
			t.Fatalf("DeleteTOTP: %v", err)
		}
		if _, err := store.GetActiveTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetActiveTOTP after DeleteTOTP = %v, want ErrTOTPNotEnrolled", err)
		}
		if _, err := store.GetPendingTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
			t.Fatalf("GetPendingTOTP after DeleteTOTP = %v, want ErrTOTPNotEnrolled", err)
		}
	})

	t.Run("DeleteTOTPForAnUnenrolledUserIsNotAnError", func(t *testing.T) {
		store := factory()
		if err := store.DeleteTOTP(ctx, uniqueID("user")); err != nil {
			t.Fatalf("DeleteTOTP with nothing to delete: %v", err)
		}
	})

	t.Run("ConcurrentConfirmEnrollmentHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			cred := newTOTPCredential(userID)
			if err := store.EnrollPending(ctx, cred); err != nil {
				t.Fatalf("iteration %d: EnrollPending: %v", i, err)
			}

			// One pending enrollment, many callers presenting the same
			// pendingID. A store that reads the pending row, compares, and
			// then writes promotes it more than once.
			errs := race(racers, func(int) error {
				_, err := store.ConfirmEnrollment(ctx, userID, cred.ID, 42)
				return err
			})
			exactlyOneWinner(t, errs, totp.ErrTOTPNotEnrolled,
				fmt.Sprintf("iteration %d: concurrent ConfirmEnrollment", i))
		}
	})

	t.Run("ConfirmEnrollmentIsAtomicAgainstConcurrentEnrollPending", func(t *testing.T) {
		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			first := newTOTPCredential(userID)
			if err := store.EnrollPending(ctx, first); err != nil {
				t.Fatalf("iteration %d: EnrollPending: %v", i, err)
			}
			second := newTOTPCredential(userID)

			// Exactly one of these may take effect. If the confirmation lands
			// first the user has an active factor, so the enrollment must be
			// refused; if the enrollment lands first the pending row no longer
			// matches pendingID, so the confirmation must be refused. A store
			// that splits either check from its write lets both through.
			var confirmed *totp.Credential
			errs := race(2, func(g int) error {
				if g == 0 {
					got, err := store.ConfirmEnrollment(ctx, userID, first.ID, 42)
					confirmed = got
					return err
				}
				return store.EnrollPending(ctx, second)
			})
			confirmErr, enrollErr := errs[0], errs[1]

			switch {
			case confirmErr == nil && enrollErr == nil:
				t.Fatalf("iteration %d: ConfirmEnrollment and EnrollPending both succeeded — the check and the write are not atomic", i)
			case confirmErr != nil && enrollErr != nil:
				t.Fatalf("iteration %d: both failed (confirm %v, enroll %v) — one of them had to win", i, confirmErr, enrollErr)
			case confirmErr == nil:
				if !errors.Is(enrollErr, totp.ErrTOTPAlreadyEnrolled) {
					t.Fatalf("iteration %d: confirmation won, so EnrollPending must report ErrTOTPAlreadyEnrolled, got %v", i, enrollErr)
				}
				if confirmed == nil || confirmed.ID != first.ID {
					t.Fatalf("iteration %d: ConfirmEnrollment returned %+v, want the promoted %q", i, confirmed, first.ID)
				}
				active, err := store.GetActiveTOTP(ctx, userID)
				if err != nil {
					t.Fatalf("iteration %d: GetActiveTOTP: %v", i, err)
				}
				if active.ID != first.ID {
					t.Fatalf("iteration %d: active credential = %q, want the confirmed %q", i, active.ID, first.ID)
				}
			default:
				if !errors.Is(confirmErr, totp.ErrTOTPNotEnrolled) {
					t.Fatalf("iteration %d: enrollment won, so ConfirmEnrollment must report ErrTOTPNotEnrolled, got %v", i, confirmErr)
				}
				if _, err := store.GetActiveTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
					t.Fatalf("iteration %d: enrollment won but an active credential exists: %v", i, err)
				}
				pending, err := store.GetPendingTOTP(ctx, userID)
				if err != nil {
					t.Fatalf("iteration %d: GetPendingTOTP: %v", i, err)
				}
				if pending.ID != second.ID {
					t.Fatalf("iteration %d: pending = %q, want the enrolled %q", i, pending.ID, second.ID)
				}
			}
		}
	})

	t.Run("DeleteTOTPIsAtomicAgainstConcurrentConfirmEnrollment", func(t *testing.T) {
		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			enrollAndConfirm(t, store, userID, 1)
			replacement := newTOTPCredential(userID)
			if err := store.ReplacePending(ctx, replacement); err != nil {
				t.Fatalf("iteration %d: ReplacePending: %v", i, err)
			}

			// Whichever order these land in, the user must end up with
			// nothing. A store that deletes the active row and then the
			// pending one lets a promotion slip between the two deletes and
			// resurrect an active factor the caller believed it had removed.
			race(2, func(g int) error {
				if g == 0 {
					return store.DeleteTOTP(ctx, userID)
				}
				_, err := store.ConfirmEnrollment(ctx, userID, replacement.ID, 2)
				return err
			})

			if active, err := store.GetActiveTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
				t.Fatalf("iteration %d: active credential %+v survived DeleteTOTP (err %v) — the two removals are not atomic", i, active, err)
			}
			if _, err := store.GetPendingTOTP(ctx, userID); !errors.Is(err, totp.ErrTOTPNotEnrolled) {
				t.Fatalf("iteration %d: a pending enrollment survived DeleteTOTP: %v", i, err)
			}
		}
	})

	t.Run("ConcurrentSaveTOTPNeverLowersTheCounter", func(t *testing.T) {
		const racers = 8

		counters := make([]uint64, racers)
		var counter uint64
		for n := range counters {
			counter++
			counters[n] = counter
		}
		highest := counters[racers-1]

		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			active := enrollAndConfirm(t, store, userID, 0)

			// Racers save an ascending counter each, in whatever order the
			// runtime picks. Whenever the highest lands, nothing below it may
			// be accepted afterwards, so the stored counter must end at the
			// highest — a store that just overwrites ends wherever the last
			// writer happened to be.
			race(racers, func(g int) error {
				write := *active
				write.LastUsedCounter = counters[g]
				return store.SaveTOTP(ctx, &write)
			})

			got, err := store.GetActiveTOTP(ctx, userID)
			if err != nil {
				t.Fatalf("iteration %d: GetActiveTOTP: %v", i, err)
			}
			if got.LastUsedCounter != highest {
				t.Fatalf("iteration %d: LastUsedCounter = %d, want %d — a save that lowers the counter must be rejected",
					i, got.LastUsedCounter, highest)
			}
		}
	})
}

// enrollAndConfirm puts userID's active factor in place at the given counter
// and returns it, for subtests whose subject is what happens afterwards.
func enrollAndConfirm(t *testing.T, store totp.Store, userID string, counter uint64) *totp.Credential {
	t.Helper()

	ctx := context.Background()
	cred := newTOTPCredential(userID)
	if err := store.EnrollPending(ctx, cred); err != nil {
		t.Fatalf("EnrollPending (setup): %v", err)
	}
	active, err := store.ConfirmEnrollment(ctx, userID, cred.ID, counter)
	if err != nil {
		t.Fatalf("ConfirmEnrollment (setup): %v", err)
	}
	return active
}

// newTOTPCredential builds an unverified enrollment for userID. The secret is
// a placeholder: a store never interprets it.
func newTOTPCredential(userID string) *totp.Credential {
	id := uniqueID("totp")
	return &totp.Credential{
		ID:        id,
		UserID:    userID,
		Secret:    "JBSWY3DPEHPK3PXP" + id,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
}
