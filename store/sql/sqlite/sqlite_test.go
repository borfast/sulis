// Package sqlite_test runs the public conformance suite against every store
// in package sqlite.
//
// It is an external test package for the same reason memstore's is: the suite
// imports sulis and its subpackages, and so does the package under test.
package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/passkey"
	"github.com/borfast/sulis/recovery"
	"github.com/borfast/sulis/store/sql/sqlite"
	"github.com/borfast/sulis/storetest"
	"github.com/borfast/sulis/totp"
)

// openDB opens one empty database file for the whole test function and closes
// it when the test ends.
func openDB(t *testing.T) *sqlite.DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sulis.db")
	db, err := sqlite.Open(context.Background(), sqlite.FileDSN(path))
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing the database: %v", err)
		}
	})
	return db
}

// truncate empties every table, which is how a database-backed factory
// satisfies storetest's "a store observing no state from any earlier call"
// contract. The suite names this explicitly as an acceptable reset ("an empty
// database, a truncated schema, a new map") and asks that it be cheap,
// because the concurrency subtests call the factory once per iteration —
// hundreds of times per package run. Emptying eight small tables on an open
// handle is; creating, migrating, and holding open a fresh database file
// every time is not, and would leave hundreds of handles alive at once, since
// the factory closure has no hook to close the store it returned.
func truncate(t *testing.T, db *sqlite.DB) {
	t.Helper()

	ctx := context.Background()
	for _, table := range tables(t, db.SQL()) {
		if _, err := db.SQL().ExecContext(ctx, `DELETE FROM `+table); err != nil {
			t.Fatalf("emptying %s: %v", table, err)
		}
	}
}

// tables lists the schema's own tables, read back from the database rather
// than hard-coded here so a table added to schema.sql is emptied without this
// file having to be remembered.
func tables(t *testing.T, db *sql.DB) []string {
	t.Helper()

	rows, err := db.QueryContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("listing tables: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("listing tables: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("listing tables: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("the migrated database has no tables")
	}
	return names
}

func TestUserStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunUserStore(t, func() sulis.UserStore {
		truncate(t, db)
		return db.UserStore()
	})
}

func TestSessionStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunSessionStore(t, func() sulis.SessionStore {
		truncate(t, db)
		return db.SessionStore()
	})
}

func TestTokenStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunTokenStore(t, func() sulis.TokenStore {
		truncate(t, db)
		return db.TokenStore()
	})
}

func TestPasskeyStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunPasskeyStore(t, func() passkey.Store {
		truncate(t, db)
		return db.PasskeyStore()
	})
}

func TestPasskeyChallengeStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunPasskeyChallengeStore(t, func() passkey.ChallengeStore {
		truncate(t, db)
		return db.ChallengeStore()
	})
}

func TestTOTPStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunTOTPStore(t, func() totp.Store {
		truncate(t, db)
		return db.TOTPStore()
	})
}

func TestRecoveryStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunRecoveryStore(t, func() recovery.Store {
		truncate(t, db)
		return db.RecoveryStore()
	})
}

// TestMemoryDSNRoundTrips covers the in-memory DSN the package offers for
// tests and examples, which the conformance runs above (deliberately on real
// files) never exercise.
func TestMemoryDSNRoundTrips(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.MemoryDSN())
	if err != nil {
		t.Fatalf("Open(MemoryDSN()): %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing the database: %v", err)
		}
	})

	users := db.UserStore()
	want := &sulis.User{ID: "user-1", Email: "someone@example.test", PasswordHash: "argon2id$x"}
	if err := users.CreateUser(ctx, want); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := users.GetUserByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Email != want.Email || got.PasswordHash != want.PasswordHash {
		t.Fatalf("round-tripped user = %+v, want %+v", got, want)
	}
}

// TestEmailUniquenessIsCaseInsensitive pins the schema's COLLATE NOCASE
// choice, which is a deliberate divergence from memstore's exact comparison
// and so cannot live in storetest: sulis lowercases an address long before a
// store sees it, and the store refusing the confusable duplicate anyway is
// defense in depth for a caller that skipped normalization.
func TestEmailUniquenessIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	users := db.UserStore()

	if err := users.CreateUser(ctx, &sulis.User{ID: "user-1", Email: "someone@example.test"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	err := users.CreateUser(ctx, &sulis.User{ID: "user-2", Email: "SomeOne@Example.Test"})
	if !errors.Is(err, sulis.ErrUserAlreadyExists) {
		t.Fatalf("CreateUser with a differently-cased duplicate = %v, want ErrUserAlreadyExists", err)
	}
}

// The tests below cover the behaviors this package commits to that the store
// interfaces do not require of every implementation, and so cannot live in
// storetest without holding conforming stores to more than their contract.

// TestConsumeChallengeRefusesAnExpiredChallenge pins the TTL the
// ChallengeStore interface asks implementations to apply ("roughly five
// minutes, matching the lifetime of a WebAuthn ceremony") but does not
// express in any method. storetest cannot check it: a store is conforming
// without it.
func TestConsumeChallengeRefusesAnExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	challenges := db.ChallengeStore()
	// The shortest lifetime the field accepts: the round trip through SQLite
	// between saving and consuming is microseconds at best, so this is
	// reliably expired without the test sleeping for it.
	challenges.TTL = time.Nanosecond

	if err := challenges.SaveChallenge(ctx, "register:user-1", []byte("session-data")); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}
	if data, err := challenges.ConsumeChallenge(ctx, "register:user-1"); err == nil {
		t.Fatalf("ConsumeChallenge returned (%q, nil) for an expired challenge, want an error", data)
	}
	// The refused read still burned the row, the same direction consumeToken
	// and RefreshSession take: nothing is left for a second attempt.
	var n int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_challenges`).Scan(&n); err != nil {
		t.Fatalf("counting challenges: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d challenge rows remain after a refused consume, want 0", n)
	}
}

// TestDeleteExpiredChallengesRemovesOnlyExpiredOnes covers the optional sweep
// this package offers for challenges nobody ever finished, which the
// interface has no method for.
func TestDeleteExpiredChallengesRemovesOnlyExpiredOnes(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)

	stale := db.ChallengeStore()
	stale.TTL = time.Nanosecond
	if err := stale.SaveChallenge(ctx, "abandoned", []byte("stale")); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}
	live := db.ChallengeStore()
	if err := live.SaveChallenge(ctx, "in-flight", []byte("live")); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}

	if err := live.DeleteExpiredChallenges(ctx); err != nil {
		t.Fatalf("DeleteExpiredChallenges: %v", err)
	}
	if _, err := live.ConsumeChallenge(ctx, "abandoned"); !errors.Is(err, sqlite.ErrChallengeNotFound) {
		t.Fatalf("ConsumeChallenge(abandoned) = %v, want ErrChallengeNotFound", err)
	}
	got, err := live.ConsumeChallenge(ctx, "in-flight")
	if err != nil {
		t.Fatalf("an unexpired challenge was swept: %v", err)
	}
	if string(got) != "live" {
		t.Fatalf("ConsumeChallenge = %q, want %q", got, "live")
	}
}

// TestNewAdoptsACallerOwnedHandle covers the other construction path, where
// the caller opens and configures the pool and applies the schema itself.
func TestNewAdoptsACallerOwnedHandle(t *testing.T) {
	ctx := context.Background()
	handle, err := sql.Open(sqlite.DriverName, sqlite.MemoryDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	handle.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Errorf("closing the handle: %v", err)
		}
	})
	if err := sqlite.Migrate(ctx, handle); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Migrating twice must be safe: the schema is written with IF NOT EXISTS
	// so an adopter running it on every boot is not punished for it.
	if err := sqlite.Migrate(ctx, handle); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	db := sqlite.New(handle)
	if db.SQL() != handle {
		t.Fatal("SQL() returned a different handle than the one passed to New")
	}
	if err := db.RecoveryStore().ReplaceCodes(ctx, "user-1", []string{"hash-a", "hash-b"}); err != nil {
		t.Fatalf("ReplaceCodes: %v", err)
	}
	count, err := db.RecoveryStore().CountCodes(ctx, "user-1")
	if err != nil {
		t.Fatalf("CountCodes: %v", err)
	}
	if count != 2 {
		t.Fatalf("CountCodes = %d, want 2", count)
	}
}

// TestFileDSNEscapesThePath pins the escaping, which fails silently rather
// than loudly when it is missing: a raw "?" in a path terminates the URI, and
// SQLite creates and uses a different file than the caller named.
func TestFileDSNEscapesThePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "awkward?name#here")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	path := filepath.Join(dir, "sulis.db")

	db, err := sqlite.Open(context.Background(), sqlite.FileDSN(path))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the database was not created at the path asked for: %v", err)
	}
}

// TestOpenNeverPutsTheDSNInTheErrorMessage is the SQLite half of the ruling
// its Postgres sibling records as
// TestSearchPathDSN/NeverPutsTheDSNOrThePasswordInTheErrorMessage: a DSN
// never reaches an error string, not even wrapped.
//
// A SQLite DSN is a file path and a set of pragmas rather than a URL with a
// password in it, which is why this was the last place the rule was not
// applied — but the rule is deliberately absolute rather than
// scheme-by-scheme. A path is deployment topology, an encrypted build's key
// pragma would be a credential outright, and the value of a rule like this
// comes entirely from never having to decide case by case whether this
// particular DSN is the sensitive kind. Open used to interpolate it with
// %q into both of its errors; the sibling package interpolates nothing.
//
// What the driver's own wrapped error says is not this package's to
// control — modernc.org/sqlite reports a URL-escape failure by quoting the
// offending escape back, the same residual the Postgres sibling carries
// from pgx — so this asserts on the message sulis composes, using a failure
// (a database file under a directory that does not exist) whose driver
// error names nothing at all.
func TestOpenNeverPutsTheDSNInTheErrorMessage(t *testing.T) {
	const marker = "sup3rSecretDirectory"
	path := filepath.Join(t.TempDir(), marker, "sulis.db")
	dsn := sqlite.FileDSN(path)

	db, err := sqlite.Open(context.Background(), dsn)
	if err == nil {
		_ = db.Close()
		t.Fatalf("Open(%q) succeeded, so this test no longer exercises the error path", dsn)
	}

	msg := err.Error()
	for _, secret := range []string{dsn, path, marker} {
		if strings.Contains(msg, secret) {
			t.Fatalf("Open error = %q, which contains %q — a DSN must never reach an error string", msg, secret)
		}
	}
}

// TestEveryMethodFailsClosedOnAnUnavailableDatabase walks every store method
// with the handle already closed and requires every method to report the
// failure.
//
// This is the property storetest cannot check, because it needs a store it
// can break on purpose: a method that swallowed a database error and returned
// nil would tell sulis a write landed when it did not — a revoked session
// that is still live, a consumed token that can be consumed again, a
// last-credential guard that reported success without deleting anything.
// Silence is the one unacceptable answer here, so the assertion is only that
// there IS an error, not which.
func TestEveryMethodFailsClosedOnAnUnavailableDatabase(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.MemoryDSN())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	now := time.Now()
	calls := map[string]func() error{
		"CreateUser":       func() error { return db.UserStore().CreateUser(ctx, &sulis.User{ID: "u"}) },
		"GetUserByID":      func() error { _, err := db.UserStore().GetUserByID(ctx, "u"); return err },
		"GetUserByEmail":   func() error { _, err := db.UserStore().GetUserByEmail(ctx, "e"); return err },
		"UpdateUser":       func() error { return db.UserStore().UpdateUser(ctx, &sulis.User{ID: "u"}) },
		"DeleteUser":       func() error { return db.UserStore().DeleteUser(ctx, "u") },
		"CreateSession":    func() error { return db.SessionStore().CreateSession(ctx, &sulis.Session{ID: "s"}) },
		"GetSession":       func() error { _, err := db.SessionStore().GetSessionByTokenHash(ctx, "h"); return err },
		"ListUserSessions": func() error { _, err := db.SessionStore().ListUserSessions(ctx, "u"); return err },
		"DeleteSession":    func() error { return db.SessionStore().DeleteSession(ctx, "u", "s") },
		"DeleteUserSessions": func() error {
			return db.SessionStore().DeleteUserSessions(ctx, "u")
		},
		"DeleteUserSessionsExcept": func() error {
			return db.SessionStore().DeleteUserSessionsExcept(ctx, "u", "s")
		},
		"CleanExpired": func() error { return db.SessionStore().CleanExpired(ctx) },
		"UpdateAuthenticatedAt": func() error {
			return db.SessionStore().UpdateAuthenticatedAt(ctx, "s", now)
		},
		"TouchSession": func() error { return db.SessionStore().TouchSession(ctx, "s", now, &now) },
		"CreateToken":  func() error { return db.TokenStore().CreateToken(ctx, &sulis.Token{ID: "t"}) },
		"ConsumeToken": func() error {
			_, err := db.TokenStore().ConsumeToken(ctx, "h", sulis.TokenPurposeMagicLink)
			return err
		},
		"DeleteExpired": func() error { return db.TokenStore().DeleteExpiredTokens(ctx) },
		"DeleteUserTokens": func() error {
			return db.TokenStore().DeleteUserTokens(ctx, "u", sulis.TokenPurposeMagicLink)
		},
		"SaveCredential": func() error {
			return db.PasskeyStore().SaveCredential(ctx, &passkey.Credential{ID: "c"})
		},
		"GetCredentialsByUserID": func() error {
			_, err := db.PasskeyStore().GetCredentialsByUserID(ctx, "u")
			return err
		},
		"GetCredentialByID": func() error {
			_, err := db.PasskeyStore().GetCredentialByID(ctx, []byte("c"))
			return err
		},
		"UpdateCredentialAfterLogin": func() error {
			return db.PasskeyStore().UpdateCredentialAfterLogin(ctx, []byte("c"), 1, true, now)
		},
		"DeleteCredential": func() error {
			return db.PasskeyStore().DeleteCredential(ctx, "u", "c", false)
		},
		"DeleteCredentialsByUserID": func() error {
			return db.PasskeyStore().DeleteCredentialsByUserID(ctx, "u")
		},
		"RenameCredential":        func() error { return db.PasskeyStore().RenameCredential(ctx, "c", "n") },
		"SaveChallenge":           func() error { return db.ChallengeStore().SaveChallenge(ctx, "k", []byte("d")) },
		"ConsumeChallenge":        func() error { _, err := db.ChallengeStore().ConsumeChallenge(ctx, "k"); return err },
		"DeleteExpiredChallenges": func() error { return db.ChallengeStore().DeleteExpiredChallenges(ctx) },
		"GetActiveTOTP":           func() error { _, err := db.TOTPStore().GetActiveTOTP(ctx, "u"); return err },
		"GetPendingTOTP":          func() error { _, err := db.TOTPStore().GetPendingTOTP(ctx, "u"); return err },
		"EnrollPending": func() error {
			return db.TOTPStore().EnrollPending(ctx, &totp.Credential{ID: "p", UserID: "u"})
		},
		"ReplacePending": func() error {
			return db.TOTPStore().ReplacePending(ctx, &totp.Credential{ID: "p", UserID: "u"})
		},
		"ConfirmEnrollment": func() error {
			_, err := db.TOTPStore().ConfirmEnrollment(ctx, "u", "p", 1)
			return err
		},
		"SaveTOTP":     func() error { return db.TOTPStore().SaveTOTP(ctx, &totp.Credential{ID: "a", UserID: "u"}) },
		"DeleteTOTP":   func() error { return db.TOTPStore().DeleteTOTP(ctx, "u") },
		"ReplaceCodes": func() error { return db.RecoveryStore().ReplaceCodes(ctx, "u", []string{"h"}) },
		"ConsumeCode":  func() error { return db.RecoveryStore().ConsumeCode(ctx, "u", "h") },
		"CountCodes":   func() error { _, err := db.RecoveryStore().CountCodes(ctx, "u"); return err },
		"DeleteCodes":  func() error { return db.RecoveryStore().DeleteCodes(ctx, "u") },
	}

	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s returned nil against a closed database — a store that swallows a write failure tells sulis a write landed when it did not", name)
		}
	}
}
