package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/borfast/sulis/passkey"

	"github.com/go-webauthn/webauthn/protocol"
)

// RunPasskeyStore checks an implementation of passkey.Store against the
// contract documented on that interface.
//
// DeleteCredential is where the danger lives. The membership check, the
// remaining-count check, and the removal must be one atomic operation with
// respect to any concurrent call for the same user, or two goroutines each
// deleting one of a user's last two credentials both observe count == 2, both
// pass the allowLast == false guard, and both succeed — leaving the user with
// zero credentials, which is precisely the lockout the guard exists to
// prevent, reached through the guarded path. The suite races that case
// directly. It also pins the cross-user refusal (ErrPasskeyNotFound, not a
// silent success) and the bookkeeping UpdateCredentialAfterLogin must persist,
// which go-webauthn re-checks on every subsequent ceremony: a store that drops
// BackupState or SignCount breaks the next login rather than this one.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunPasskeyStore(t *testing.T, factory func() passkey.Store) {
	t.Helper()

	ctx := context.Background()

	t.Run("SaveCredentialRoundTrips", func(t *testing.T) {
		store := factory()
		cred := newCredential(uniqueID("user"))
		cred.Name = "Work laptop"
		cred.SignCount = 7
		cred.BackupEligible = true
		cred.BackupState = true
		cred.Discoverable = true
		cred.Transports = []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid}
		if err := store.SaveCredential(ctx, cred); err != nil {
			t.Fatalf("SaveCredential: %v", err)
		}

		got, err := store.GetCredentialByID(ctx, cred.CredentialID)
		if err != nil {
			t.Fatalf("GetCredentialByID: %v", err)
		}
		assertCredentialMatches(t, "GetCredentialByID", got, cred)

		byUser, err := store.GetCredentialsByUserID(ctx, cred.UserID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(byUser) != 1 {
			t.Fatalf("GetCredentialsByUserID returned %d credentials, want 1", len(byUser))
		}
		assertCredentialMatches(t, "GetCredentialsByUserID", &byUser[0], cred)
	})

	t.Run("GetCredentialsByUserIDReturnsOnlyThatUsersCredentials", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		mine := []*passkey.Credential{newCredential(userID), newCredential(userID)}
		theirs := newCredential(uniqueID("user"))
		for _, cred := range append(append([]*passkey.Credential{}, mine...), theirs) {
			if err := store.SaveCredential(ctx, cred); err != nil {
				t.Fatalf("SaveCredential: %v", err)
			}
		}

		got, err := store.GetCredentialsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(got) != len(mine) {
			t.Fatalf("GetCredentialsByUserID returned %d credentials, want %d", len(got), len(mine))
		}
		for _, cred := range got {
			if cred.UserID != userID {
				t.Fatalf("GetCredentialsByUserID(%q) returned a credential owned by %q", userID, cred.UserID)
			}
		}
	})

	t.Run("GetCredentialsByUserIDForAnUnknownUserReturnsNothing", func(t *testing.T) {
		store := factory()
		got, err := store.GetCredentialsByUserID(ctx, uniqueID("absent"))
		if err != nil {
			t.Fatalf("GetCredentialsByUserID for an unknown user: %v — no credentials is not an error", err)
		}
		if len(got) != 0 {
			t.Fatalf("GetCredentialsByUserID for an unknown user returned %d credentials, want 0", len(got))
		}
	})

	t.Run("GetCredentialByIDUnknownReturnsAnError", func(t *testing.T) {
		store := factory()
		// The interface does not name the error, only that the lookup fails:
		// passkey.Service normalizes whatever comes back. Returning a nil
		// credential with a nil error would make every caller dereference it.
		got, err := store.GetCredentialByID(ctx, []byte(uniqueID("absent")))
		if err == nil {
			t.Fatalf("GetCredentialByID for an unknown credential returned (%+v, nil), want an error", got)
		}
	})

	t.Run("UpdateCredentialAfterLoginPersistsAllThreeFields", func(t *testing.T) {
		store := factory()
		cred := newCredential(uniqueID("user"))
		cred.SignCount = 3
		cred.BackupEligible = true
		cred.BackupState = false
		if err := store.SaveCredential(ctx, cred); err != nil {
			t.Fatalf("SaveCredential: %v", err)
		}

		lastUsed := time.Now().UTC().Truncate(time.Second)
		if err := store.UpdateCredentialAfterLogin(ctx, cred.CredentialID, 9, true, lastUsed); err != nil {
			t.Fatalf("UpdateCredentialAfterLogin: %v", err)
		}

		// Both read paths must observe the update. go-webauthn re-checks the
		// sign count and the backup state against what the store hands it on
		// every later ceremony, and Service reloads through both.
		byID, err := store.GetCredentialByID(ctx, cred.CredentialID)
		if err != nil {
			t.Fatalf("GetCredentialByID: %v", err)
		}
		assertLoginBookkeeping(t, "GetCredentialByID", byID, 9, true, lastUsed)

		byUser, err := store.GetCredentialsByUserID(ctx, cred.UserID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(byUser) != 1 {
			t.Fatalf("GetCredentialsByUserID returned %d credentials, want 1", len(byUser))
		}
		assertLoginBookkeeping(t, "GetCredentialsByUserID", &byUser[0], 9, true, lastUsed)
	})

	t.Run("DeleteCredentialRemovesANonLastCredential", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		first, second := newCredential(userID), newCredential(userID)
		for _, cred := range []*passkey.Credential{first, second} {
			if err := store.SaveCredential(ctx, cred); err != nil {
				t.Fatalf("SaveCredential: %v", err)
			}
		}

		if err := store.DeleteCredential(ctx, userID, first.ID, false); err != nil {
			t.Fatalf("DeleteCredential: %v", err)
		}
		remaining, err := store.GetCredentialsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(remaining) != 1 || remaining[0].ID != second.ID {
			t.Fatalf("remaining credentials = %+v, want only %q", remaining, second.ID)
		}
	})

	t.Run("DeleteCredentialRefusesTheLastCredentialWithoutAllowLast", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		only := newCredential(userID)
		if err := store.SaveCredential(ctx, only); err != nil {
			t.Fatalf("SaveCredential: %v", err)
		}

		if err := store.DeleteCredential(ctx, userID, only.ID, false); !errors.Is(err, passkey.ErrLastCredential) {
			t.Fatalf("DeleteCredential error = %v, want ErrLastCredential", err)
		}
		remaining, err := store.GetCredentialsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(remaining) != 1 {
			t.Fatalf("the refused delete still removed the credential: %d remain, want 1", len(remaining))
		}
	})

	t.Run("DeleteCredentialRemovesTheLastCredentialWithAllowLast", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		only := newCredential(userID)
		if err := store.SaveCredential(ctx, only); err != nil {
			t.Fatalf("SaveCredential: %v", err)
		}

		if err := store.DeleteCredential(ctx, userID, only.ID, true); err != nil {
			t.Fatalf("DeleteCredential with allowLast: %v", err)
		}
		remaining, err := store.GetCredentialsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(remaining) != 0 {
			t.Fatalf("%d credentials remain, want 0", len(remaining))
		}
	})

	t.Run("DeleteCredentialForAnotherUserReturnsErrPasskeyNotFound", func(t *testing.T) {
		store := factory()
		ownerID := uniqueID("owner")
		owned := []*passkey.Credential{newCredential(ownerID), newCredential(ownerID)}
		attackerID := uniqueID("attacker")
		attackerCreds := []*passkey.Credential{newCredential(attackerID), newCredential(attackerID)}
		for _, cred := range append(append([]*passkey.Credential{}, owned...), attackerCreds...) {
			if err := store.SaveCredential(ctx, cred); err != nil {
				t.Fatalf("SaveCredential: %v", err)
			}
		}

		// allowLast is true so that a store which refuses for the wrong
		// reason (the count, not the ownership) cannot pass by accident.
		if err := store.DeleteCredential(ctx, attackerID, owned[0].ID, true); !errors.Is(err, passkey.ErrPasskeyNotFound) {
			t.Fatalf("cross-user DeleteCredential error = %v, want ErrPasskeyNotFound", err)
		}
		remaining, err := store.GetCredentialsByUserID(ctx, ownerID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(remaining) != len(owned) {
			t.Fatalf("the owner has %d credentials after another user's delete, want %d", len(remaining), len(owned))
		}
	})

	t.Run("DeleteCredentialUnknownIDReturnsErrPasskeyNotFound", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		cred := newCredential(userID)
		if err := store.SaveCredential(ctx, cred); err != nil {
			t.Fatalf("SaveCredential: %v", err)
		}
		if err := store.DeleteCredential(ctx, userID, uniqueID("absent"), true); !errors.Is(err, passkey.ErrPasskeyNotFound) {
			t.Fatalf("DeleteCredential for an unknown id error = %v, want ErrPasskeyNotFound", err)
		}
	})

	t.Run("DeleteCredentialsByUserIDRemovesOnlyThatUsersCredentials", func(t *testing.T) {
		store := factory()
		userID := uniqueID("user")
		otherID := uniqueID("user")
		mine := []*passkey.Credential{newCredential(userID), newCredential(userID)}
		theirs := newCredential(otherID)
		for _, cred := range append(append([]*passkey.Credential{}, mine...), theirs) {
			if err := store.SaveCredential(ctx, cred); err != nil {
				t.Fatalf("SaveCredential: %v", err)
			}
		}

		// No last-credential guard applies here, by design: deleting a whole
		// account is a stronger action the caller has already gated.
		if err := store.DeleteCredentialsByUserID(ctx, userID); err != nil {
			t.Fatalf("DeleteCredentialsByUserID: %v", err)
		}
		remaining, err := store.GetCredentialsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(remaining) != 0 {
			t.Fatalf("%d credentials remain for the deleted user, want 0", len(remaining))
		}
		if _, err := store.GetCredentialByID(ctx, mine[0].CredentialID); err == nil {
			t.Fatal("GetCredentialByID still finds a credential DeleteCredentialsByUserID removed")
		}
		survivors, err := store.GetCredentialsByUserID(ctx, otherID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(survivors) != 1 {
			t.Fatalf("another user has %d credentials, want 1", len(survivors))
		}
	})

	t.Run("RenameCredentialSetsName", func(t *testing.T) {
		store := factory()
		cred := newCredential(uniqueID("user"))
		if err := store.SaveCredential(ctx, cred); err != nil {
			t.Fatalf("SaveCredential: %v", err)
		}

		if err := store.RenameCredential(ctx, cred.ID, "YubiKey 5C"); err != nil {
			t.Fatalf("RenameCredential: %v", err)
		}
		got, err := store.GetCredentialByID(ctx, cred.CredentialID)
		if err != nil {
			t.Fatalf("GetCredentialByID: %v", err)
		}
		if got.Name != "YubiKey 5C" {
			t.Errorf("Name = %q, want %q", got.Name, "YubiKey 5C")
		}
		byUser, err := store.GetCredentialsByUserID(ctx, cred.UserID)
		if err != nil {
			t.Fatalf("GetCredentialsByUserID: %v", err)
		}
		if len(byUser) != 1 || byUser[0].Name != "YubiKey 5C" {
			t.Fatalf("GetCredentialsByUserID = %+v, want one credential named %q", byUser, "YubiKey 5C")
		}
	})

	t.Run("RenameCredentialUnknownIDReturnsErrPasskeyNotFound", func(t *testing.T) {
		store := factory()
		if err := store.RenameCredential(ctx, uniqueID("absent"), "Nowhere"); !errors.Is(err, passkey.ErrPasskeyNotFound) {
			t.Fatalf("RenameCredential for an unknown id error = %v, want ErrPasskeyNotFound", err)
		}
	})

	t.Run("ConcurrentDeleteCredentialNeverEmptiesTheGuardedUser", func(t *testing.T) {
		const racers = 2

		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			creds := []*passkey.Credential{newCredential(userID), newCredential(userID)}
			for _, cred := range creds {
				if err := store.SaveCredential(ctx, cred); err != nil {
					t.Fatalf("iteration %d: SaveCredential: %v", i, err)
				}
			}

			// Two goroutines, each deleting a different one of the user's last
			// two credentials, both with allowLast == false. A non-atomic
			// guard lets both read count == 2 and both succeed, locking the
			// user out through the very path meant to prevent that.
			errs := race(racers, func(g int) error {
				return store.DeleteCredential(ctx, userID, creds[g].ID, false)
			})
			exactlyOneWinner(t, errs, passkey.ErrLastCredential,
				fmt.Sprintf("iteration %d: concurrent DeleteCredential", i))

			remaining, err := store.GetCredentialsByUserID(ctx, userID)
			if err != nil {
				t.Fatalf("iteration %d: GetCredentialsByUserID: %v", i, err)
			}
			if len(remaining) != 1 {
				t.Fatalf("iteration %d: user has %d credentials left, want exactly 1 — zero is the lockout the guard exists to prevent",
					i, len(remaining))
			}
		}
	})

	t.Run("ConcurrentDeleteOfTheSameCredentialHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			userID := uniqueID("user")
			target := newCredential(userID)
			spare := newCredential(userID)
			for _, cred := range []*passkey.Credential{target, spare} {
				if err := store.SaveCredential(ctx, cred); err != nil {
					t.Fatalf("iteration %d: SaveCredential: %v", i, err)
				}
			}

			// The spare keeps the last-credential guard out of the way, so the
			// only thing being tested is that one row can be deleted once.
			errs := race(racers, func(int) error {
				return store.DeleteCredential(ctx, userID, target.ID, false)
			})
			exactlyOneWinner(t, errs, passkey.ErrPasskeyNotFound,
				fmt.Sprintf("iteration %d: concurrent DeleteCredential of one id", i))
		}
	})
}

// RunPasskeyChallengeStore checks an implementation of passkey.ChallengeStore
// against the contract documented on that interface.
//
// ConsumeChallenge must fetch and delete in one operation, so that only one
// caller can ever receive a given challenge: two concurrent finishes of the
// same ceremony must not both succeed in retrieving it. A store that reads
// then deletes lets a replayed WebAuthn response be verified twice against
// the same challenge.
//
// factory must return a fresh, empty store on every call; see the package
// documentation.
func RunPasskeyChallengeStore(t *testing.T, factory func() passkey.ChallengeStore) {
	t.Helper()

	ctx := context.Background()

	t.Run("SaveChallengeRoundTrips", func(t *testing.T) {
		store := factory()
		key := uniqueID("register")
		want := []byte(`{"challenge":"` + uniqueID("c") + `"}`)
		if err := store.SaveChallenge(ctx, key, want); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}

		got, err := store.ConsumeChallenge(ctx, key)
		if err != nil {
			t.Fatalf("ConsumeChallenge: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ConsumeChallenge = %q, want %q", got, want)
		}
	})

	t.Run("ConsumeChallengeTwiceFails", func(t *testing.T) {
		store := factory()
		key := uniqueID("login")
		if err := store.SaveChallenge(ctx, key, []byte("session-data")); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}
		if _, err := store.ConsumeChallenge(ctx, key); err != nil {
			t.Fatalf("first ConsumeChallenge: %v", err)
		}

		// The error is implementation-defined — Service normalizes it to
		// ErrChallengeExpired — but there must be one.
		if data, err := store.ConsumeChallenge(ctx, key); err == nil {
			t.Fatalf("second ConsumeChallenge returned (%q, nil), want an error: a challenge must be consumable once", data)
		}
	})

	t.Run("ConsumeChallengeUnknownKeyFails", func(t *testing.T) {
		store := factory()
		if data, err := store.ConsumeChallenge(ctx, uniqueID("absent")); err == nil {
			t.Fatalf("ConsumeChallenge for an unsaved key returned (%q, nil), want an error", data)
		}
	})

	t.Run("ChallengesAreScopedToTheirKey", func(t *testing.T) {
		store := factory()
		// Keys are scoped by ceremony, not by user, precisely so concurrent
		// ceremonies for one user cannot clobber each other.
		userID := uniqueID("user")
		registerKey := "register:" + userID
		loginKey := "login:" + userID
		if err := store.SaveChallenge(ctx, registerKey, []byte("registration")); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}
		if err := store.SaveChallenge(ctx, loginKey, []byte("login")); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}

		got, err := store.ConsumeChallenge(ctx, registerKey)
		if err != nil {
			t.Fatalf("ConsumeChallenge(register): %v", err)
		}
		if string(got) != "registration" {
			t.Fatalf("ConsumeChallenge(register) = %q, want %q", got, "registration")
		}
		got, err = store.ConsumeChallenge(ctx, loginKey)
		if err != nil {
			t.Fatalf("ConsumeChallenge(login): %v", err)
		}
		if string(got) != "login" {
			t.Fatalf("ConsumeChallenge(login) = %q, want %q", got, "login")
		}
	})

	t.Run("SaveChallengeReplacesAnEarlierValueForTheSameKey", func(t *testing.T) {
		store := factory()
		key := uniqueID("register")
		if err := store.SaveChallenge(ctx, key, []byte("first")); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}
		if err := store.SaveChallenge(ctx, key, []byte("second")); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}

		got, err := store.ConsumeChallenge(ctx, key)
		if err != nil {
			t.Fatalf("ConsumeChallenge: %v", err)
		}
		if string(got) != "second" {
			t.Fatalf("ConsumeChallenge = %q, want the most recently saved %q", got, "second")
		}
	})

	t.Run("SaveChallengeCopiesTheCallersData", func(t *testing.T) {
		store := factory()
		key := uniqueID("register")
		data := []byte("session-data")
		if err := store.SaveChallenge(ctx, key, data); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}
		// A store that retains the caller's slice lets a caller reusing its
		// buffer rewrite a challenge it already handed over.
		copy(data, "OVERWRITTEN!")

		got, err := store.ConsumeChallenge(ctx, key)
		if err != nil {
			t.Fatalf("ConsumeChallenge: %v", err)
		}
		if string(got) != "session-data" {
			t.Fatalf("ConsumeChallenge = %q, want the data as saved (%q) — SaveChallenge must not retain the caller's slice",
				got, "session-data")
		}
	})

	t.Run("ConcurrentConsumeChallengeHasExactlyOneWinner", func(t *testing.T) {
		const racers = 8

		for i := range raceIterations() {
			store := factory()
			key := uniqueID("login")
			want := []byte("session-data")
			if err := store.SaveChallenge(ctx, key, want); err != nil {
				t.Fatalf("iteration %d: SaveChallenge: %v", i, err)
			}

			received := make([][]byte, racers)
			errs := race(racers, func(g int) error {
				data, err := store.ConsumeChallenge(ctx, key)
				received[g] = data
				return err
			})

			// The losers' error is implementation-defined, so count nils
			// rather than matching a sentinel.
			winners := 0
			for g, err := range errs {
				if err != nil {
					continue
				}
				winners++
				if !bytes.Equal(received[g], want) {
					t.Fatalf("iteration %d: goroutine %d received %q, want %q", i, g, received[g], want)
				}
			}
			if winners != 1 {
				t.Fatalf("iteration %d: %d of %d goroutines consumed the same challenge, want exactly 1 — the fetch and the delete are not atomic",
					i, winners, racers)
			}
		}
	})
}

// newCredential builds a credential for userID with unique identifiers.
func newCredential(userID string) *passkey.Credential {
	id := uniqueID("cred")
	return &passkey.Credential{
		ID:              id,
		UserID:          userID,
		CredentialID:    []byte("raw-" + id),
		PublicKey:       []byte("pubkey-" + id),
		AttestationType: "none",
		AAGUID:          []byte("aaguid-" + id),
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
	}
}

// assertCredentialMatches compares the fields a store must round-trip.
// CreatedAt is checked only for presence: databases legitimately differ on
// the precision and location they store timestamps in.
func assertCredentialMatches(t *testing.T, op string, got, want *passkey.Credential) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s returned a nil credential and a nil error", op)
	}
	if got.ID != want.ID {
		t.Errorf("%s: ID = %q, want %q", op, got.ID, want.ID)
	}
	if got.UserID != want.UserID {
		t.Errorf("%s: UserID = %q, want %q", op, got.UserID, want.UserID)
	}
	if !bytes.Equal(got.CredentialID, want.CredentialID) {
		t.Errorf("%s: CredentialID = %q, want %q", op, got.CredentialID, want.CredentialID)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Errorf("%s: PublicKey = %q, want %q", op, got.PublicKey, want.PublicKey)
	}
	if !bytes.Equal(got.AAGUID, want.AAGUID) {
		t.Errorf("%s: AAGUID = %q, want %q", op, got.AAGUID, want.AAGUID)
	}
	if got.AttestationType != want.AttestationType {
		t.Errorf("%s: AttestationType = %q, want %q", op, got.AttestationType, want.AttestationType)
	}
	if got.SignCount != want.SignCount {
		t.Errorf("%s: SignCount = %d, want %d", op, got.SignCount, want.SignCount)
	}
	if got.Name != want.Name {
		t.Errorf("%s: Name = %q, want %q", op, got.Name, want.Name)
	}
	// BackupEligible is re-checked for consistency by go-webauthn on every
	// later ceremony: a store that drops it rejects the credential's next
	// login with a flag-inconsistency error.
	if got.BackupEligible != want.BackupEligible {
		t.Errorf("%s: BackupEligible = %t, want %t", op, got.BackupEligible, want.BackupEligible)
	}
	if got.BackupState != want.BackupState {
		t.Errorf("%s: BackupState = %t, want %t", op, got.BackupState, want.BackupState)
	}
	// Discoverable is what BeginDiscoverableLogin needs in order to offer a
	// credential for usernameless login at all.
	if got.Discoverable != want.Discoverable {
		t.Errorf("%s: Discoverable = %t, want %t", op, got.Discoverable, want.Discoverable)
	}
	if len(got.Transports) != len(want.Transports) {
		t.Errorf("%s: Transports = %v, want %v", op, got.Transports, want.Transports)
	} else {
		for i := range want.Transports {
			if got.Transports[i] != want.Transports[i] {
				t.Errorf("%s: Transports = %v, want %v", op, got.Transports, want.Transports)
				break
			}
		}
	}
	if want.CreatedAt.IsZero() {
		return
	}
	if got.CreatedAt.IsZero() {
		t.Errorf("%s: CreatedAt is the zero time, want the value saved", op)
	}
}

// assertLoginBookkeeping checks the three fields
// UpdateCredentialAfterLogin must persist together.
func assertLoginBookkeeping(t *testing.T, op string, got *passkey.Credential, signCount uint32, backupState bool, lastUsedAt time.Time) {
	t.Helper()

	if got.SignCount != signCount {
		t.Errorf("%s: SignCount = %d, want %d — go-webauthn's clone detection reads this on the next ceremony",
			op, got.SignCount, signCount)
	}
	if got.BackupState != backupState {
		t.Errorf("%s: BackupState = %t, want %t", op, got.BackupState, backupState)
	}
	if got.LastUsedAt == nil {
		t.Errorf("%s: LastUsedAt is nil, want the time passed to UpdateCredentialAfterLogin", op)
	} else if !got.LastUsedAt.Equal(lastUsedAt) {
		t.Errorf("%s: LastUsedAt = %v, want %v", op, got.LastUsedAt, lastUsedAt)
	}
}
