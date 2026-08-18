// Package memstore_test runs the public conformance suite against every
// reference implementation in memstore.
//
// It is an external test package on purpose: memstore imports sulis and its
// subpackages, so a test file inside package memstore could not import
// storetest (which imports the same packages) without creating an import
// cycle.
package memstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/memstore"
	"github.com/borfast/sulis/passkey"
	"github.com/borfast/sulis/recovery"
	"github.com/borfast/sulis/storetest"
	"github.com/borfast/sulis/totp"
)

func TestUserStoreConformance(t *testing.T) {
	storetest.RunUserStore(t, func() sulis.UserStore { return memstore.NewUserStore() })
}

func TestSessionStoreConformance(t *testing.T) {
	storetest.RunSessionStore(t, func() sulis.SessionStore { return memstore.NewSessionStore() })
}

func TestTokenStoreConformance(t *testing.T) {
	storetest.RunTokenStore(t, func() sulis.TokenStore { return memstore.NewTokenStore() })
}

func TestPasskeyStoreConformance(t *testing.T) {
	storetest.RunPasskeyStore(t, func() passkey.Store { return memstore.NewPasskeyStore() })
}

func TestPasskeyChallengeStoreConformance(t *testing.T) {
	storetest.RunPasskeyChallengeStore(t, func() passkey.ChallengeStore { return memstore.NewChallengeStore() })
}

func TestTOTPStoreConformance(t *testing.T) {
	storetest.RunTOTPStore(t, func() totp.Store { return memstore.NewTOTPStore() })
}

func TestRecoveryStoreConformance(t *testing.T) {
	storetest.RunRecoveryStore(t, func() recovery.Store { return memstore.NewRecoveryStore() })
}

// The tests below cover the few behaviors memstore commits to that the store
// interfaces do not require of every implementation, and so cannot live in
// storetest without holding conforming stores to more than their contract.

func TestCreateUserRejectsADuplicateID(t *testing.T) {
	ctx := context.Background()
	store := memstore.NewUserStore()
	first := &sulis.User{ID: "user-1", Email: "first@example.test"}
	if err := store.CreateUser(ctx, first); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Two users cannot share a primary key, and silently overwriting one
	// would lose an account.
	second := &sulis.User{ID: "user-1", Email: "second@example.test"}
	if err := store.CreateUser(ctx, second); !errors.Is(err, sulis.ErrUserAlreadyExists) {
		t.Fatalf("CreateUser with a duplicate ID error = %v, want ErrUserAlreadyExists", err)
	}
	got, err := store.GetUserByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Email != first.Email {
		t.Fatalf("Email = %q, want the original %q", got.Email, first.Email)
	}
}

func TestUpdateCredentialAfterLoginReportsAnUnknownCredential(t *testing.T) {
	store := memstore.NewPasskeyStore()
	err := store.UpdateCredentialAfterLogin(context.Background(), []byte("never-registered"), 1, true, time.Now())
	if !errors.Is(err, passkey.ErrPasskeyNotFound) {
		t.Fatalf("UpdateCredentialAfterLogin error = %v, want ErrPasskeyNotFound", err)
	}
}

func TestSessionStoreLenCountsStoredSessions(t *testing.T) {
	ctx := context.Background()
	store := memstore.NewSessionStore()
	if n := store.Len(); n != 0 {
		t.Fatalf("Len = %d on a fresh store, want 0", n)
	}

	sess := &sulis.Session{ID: "session-1", UserID: "user-1", TokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if n := store.Len(); n != 1 {
		t.Fatalf("Len = %d, want 1", n)
	}
	if err := store.DeleteSession(ctx, sess.UserID, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if n := store.Len(); n != 0 {
		t.Fatalf("Len = %d after the session was deleted, want 0", n)
	}
}
