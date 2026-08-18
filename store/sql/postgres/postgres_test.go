// Package postgres_test runs the public conformance suite against every store
// in package postgres.
//
// It is an external test package for the same reason memstore's and sqlite's
// are: the suite imports sulis and its subpackages, and so does the package
// under test.
//
// # Running it
//
// Everything here that needs a database is skipped unless SULIS_POSTGRES_TEST_URL
// names one, so a contributor without PostgreSQL still runs the rest of the
// module's tests. To run these, point it at any database you are willing to
// have schemas created and dropped in:
//
//	docker run -d --name sulis-pg -e POSTGRES_PASSWORD=postgres \
//	    -e POSTGRES_DB=sulis_test -p 127.0.0.1:5432:5432 postgres:17-alpine
//	SULIS_POSTGRES_TEST_URL='postgres://postgres:postgres@127.0.0.1:5432/sulis_test?sslmode=disable' \
//	    go test -race ./postgres/...
//
// CI does the same thing through a service container; see
// .github/workflows/ci.yml.
package postgres_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/passkey"
	"github.com/borfast/sulis/recovery"
	"github.com/borfast/sulis/store/sql/postgres"
	"github.com/borfast/sulis/storetest"
	"github.com/borfast/sulis/totp"
)

// testURLEnv names the environment variable holding the connection URL these
// tests run against. Absent, every test that needs a database skips with a
// message saying how to set it.
const testURLEnv = "SULIS_POSTGRES_TEST_URL"

// testDB is one migrated schema plus the TRUNCATE that empties it.
type testDB struct {
	*postgres.DB
	truncate string
}

// dsn returns the connection URL to test against, or skips the test.
func dsn(t *testing.T) string {
	t.Helper()

	url := os.Getenv(testURLEnv)
	if url == "" {
		t.Skipf("%s is not set, so the PostgreSQL conformance suite is skipped; set it to a connection URL such as postgres://postgres:postgres@127.0.0.1:5432/sulis_test?sslmode=disable to run it",
			testURLEnv)
	}
	return url
}

// openDB gives one test function its own PostgreSQL schema, migrated and
// dropped again on cleanup.
//
// A schema per test function rather than a database per test function, and a
// TRUNCATE rather than a fresh schema per factory call: see the comment on
// truncate for why the reset has to be cheap, and note that the isolation
// bought here is what lets these tests run against a shared database, in
// parallel with another checkout, without either run seeing the other's rows.
func openDB(t *testing.T) *testDB {
	t.Helper()

	ctx := context.Background()
	url := dsn(t)

	// The schema has to exist before a handle whose search_path names it can
	// migrate into it, so it is created through a handle of its own.
	admin, err := sql.Open(postgres.DriverName, url)
	if err != nil {
		t.Fatalf("opening the administrative handle: %v", err)
	}
	defer func() {
		if err := admin.Close(); err != nil {
			t.Errorf("closing the administrative handle: %v", err)
		}
	}()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("connecting to %s: %v", testURLEnv, err)
	}

	schema := uniqueSchema(t)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+quoteIdent(schema)); err != nil {
		t.Fatalf("creating schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		// A separate handle: the one above is closed by the deferred call
		// before any cleanup runs.
		cleanup, err := sql.Open(postgres.DriverName, url)
		if err != nil {
			t.Errorf("opening a handle to drop schema %s: %v", schema, err)
			return
		}
		defer func() { _ = cleanup.Close() }()
		if _, err := cleanup.ExecContext(context.Background(), `DROP SCHEMA `+quoteIdent(schema)+` CASCADE`); err != nil {
			t.Errorf("dropping schema %s: %v", schema, err)
		}
	})

	scoped, err := postgres.SearchPathDSN(url, schema)
	if err != nil {
		t.Fatalf("SearchPathDSN: %v", err)
	}
	db, err := postgres.Open(ctx, scoped)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing the database: %v", err)
		}
	})

	return &testDB{DB: db, truncate: truncateStatement(t, db.SQL())}
}

// reset empties every table, which is how a database-backed factory satisfies
// storetest's "a store observing no state from any earlier call" contract. The
// suite names this explicitly as an acceptable reset ("an empty database, a
// truncated schema, a new map") and asks that it be cheap, because the
// concurrency subtests call the factory once per iteration — hundreds of times
// per package run. One TRUNCATE naming every table is one round trip and one
// transaction; creating and migrating a fresh schema every time is neither.
func (db *testDB) reset(t *testing.T) {
	t.Helper()

	if _, err := db.SQL().ExecContext(context.Background(), db.truncate); err != nil {
		t.Fatalf("emptying the schema: %v", err)
	}
}

// truncateStatement builds the TRUNCATE from the schema's own catalog rather
// than from a hard-coded list, so a table added to schema.sql is emptied
// without this file having to be remembered.
func truncateStatement(t *testing.T, db *sql.DB) string {
	t.Helper()

	rows, err := db.QueryContext(context.Background(),
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
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
		names = append(names, quoteIdent(name))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("listing tables: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("the migrated schema has no tables")
	}
	return `TRUNCATE ` + strings.Join(names, ", ")
}

// uniqueSchema names a schema no other run will pick.
func uniqueSchema(t *testing.T) string {
	t.Helper()

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating a schema name: %v", err)
	}
	return "sulis_test_" + hex.EncodeToString(b)
}

// quoteIdent renders a SQL identifier. Every identifier it is given here comes
// from uniqueSchema or from pg_tables, so this is belt and braces rather than
// a defence — but an identifier interpolated into DDL without quoting is the
// shape of bug worth never writing at all.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func TestUserStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunUserStore(t, func() sulis.UserStore {
		db.reset(t)
		return db.UserStore()
	})
}

func TestSessionStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunSessionStore(t, func() sulis.SessionStore {
		db.reset(t)
		return db.SessionStore()
	})
}

func TestTokenStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunTokenStore(t, func() sulis.TokenStore {
		db.reset(t)
		return db.TokenStore()
	})
}

func TestPasskeyStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunPasskeyStore(t, func() passkey.Store {
		db.reset(t)
		return db.PasskeyStore()
	})
}

func TestPasskeyChallengeStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunPasskeyChallengeStore(t, func() passkey.ChallengeStore {
		db.reset(t)
		return db.ChallengeStore()
	})
}

func TestTOTPStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunTOTPStore(t, func() totp.Store {
		db.reset(t)
		return db.TOTPStore()
	})
}

func TestRecoveryStoreConformance(t *testing.T) {
	db := openDB(t)
	storetest.RunRecoveryStore(t, func() recovery.Store {
		db.reset(t)
		return db.RecoveryStore()
	})
}

// TestEmailUniquenessIsCaseInsensitive pins the schema's UNIQUE index on
// lower(email), which is a deliberate divergence from memstore's exact
// comparison and so cannot live in storetest. It is deliberately the same test
// the SQLite store carries for its COLLATE NOCASE column: the two stores must
// agree on this, and the way to keep them agreeing is to hold them to the same
// assertion.
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

// TestGetUserByEmailIsCaseInsensitive is the other half of the same divergence:
// the lookup has to match the uniqueness rule, or an address the store refuses
// to duplicate would still be unfindable under the casing a caller used.
func TestGetUserByEmailIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	users := db.UserStore()

	if err := users.CreateUser(ctx, &sulis.User{ID: "user-1", Email: "someone@example.test"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := users.GetUserByEmail(ctx, "SomeOne@Example.Test")
	if err != nil {
		t.Fatalf("GetUserByEmail with different casing: %v", err)
	}
	if got.ID != "user-1" {
		t.Fatalf("GetUserByEmail returned %q, want user-1", got.ID)
	}
}

// TestTimestampsRoundTripToTheNanosecond pins the schema's one deliberate
// departure from idiomatic PostgreSQL. timestamptz would round this value to
// the nearest microsecond and the loss would only ever surface as a puzzling
// storetest failure, so the property is asserted here where the reason can be
// written down next to it.
func TestTimestampsRoundTripToTheNanosecond(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	sessions := db.SessionStore()

	// Nanoseconds that no microsecond-resolution column can hold.
	at := time.Date(2026, 8, 18, 12, 34, 56, 123456789, time.UTC)
	sess := &sulis.Session{
		ID: "session-1", UserID: "user-1", TokenHash: "hash-1",
		ExpiresAt: at, CreatedAt: at, AuthenticatedAt: at, LastSeenAt: at,
	}
	if err := sessions.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := sessions.GetSessionByTokenHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if !got.ExpiresAt.Equal(at) {
		t.Fatalf("ExpiresAt round-tripped as %v, want %v — a timestamp column that loses sub-microsecond precision fails the session contract",
			got.ExpiresAt.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
	}
}

// TestDeleteTOTPAndConfirmEnrollmentNeverDeadlock pins the advisory lock
// TOTPStore takes, which storetest cannot pin.
//
// DeleteTOTP writes totp_active then totp_pending; ConfirmEnrollment writes
// totp_pending then totp_active. That is a lock-order inversion, and without
// the lock that serializes the pair, PostgreSQL resolves it by detecting a
// deadlock and aborting one of them — observed as eight "deadlock detected"
// entries in the server log across 100 iterations of storetest's own
// DeleteTOTPIsAtomicAgainstConcurrentConfirmEnrollment while the lock was
// removed for a mutation test. That subtest passed anyway, because it ignores
// the errors the race returns and only inspects the state afterwards; which
// transaction PostgreSQL picks as the victim decides whether it would have
// caught anything at all.
//
// So the assertion here is the one storetest deliberately does not make: that
// neither call fails. A promotion refused because the factor was deleted first
// is a legitimate answer (ErrTOTPNotEnrolled) and is allowed; a promotion
// refused because two of this package's own transactions deadlocked is not.
func TestDeleteTOTPAndConfirmEnrollmentNeverDeadlock(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	store := db.TOTPStore()

	for i := range 50 {
		userID := fmt.Sprintf("user-%d", i)
		active := &totp.Credential{ID: fmt.Sprintf("active-%d", i), UserID: userID, Secret: "s", CreatedAt: time.Now().UTC()}
		if err := store.EnrollPending(ctx, active); err != nil {
			t.Fatalf("iteration %d: EnrollPending: %v", i, err)
		}
		if _, err := store.ConfirmEnrollment(ctx, userID, active.ID, 1); err != nil {
			t.Fatalf("iteration %d: ConfirmEnrollment (setup): %v", i, err)
		}
		replacement := &totp.Credential{ID: fmt.Sprintf("pending-%d", i), UserID: userID, Secret: "s", CreatedAt: time.Now().UTC()}
		if err := store.ReplacePending(ctx, replacement); err != nil {
			t.Fatalf("iteration %d: ReplacePending: %v", i, err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs[0] = store.DeleteTOTP(ctx, userID)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, err := store.ConfirmEnrollment(ctx, userID, replacement.ID, 2)
			if errors.Is(err, totp.ErrTOTPNotEnrolled) {
				err = nil
			}
			errs[1] = err
		}()
		close(start)
		wg.Wait()

		if errs[0] != nil {
			t.Fatalf("iteration %d: DeleteTOTP raced against ConfirmEnrollment and failed: %v", i, errs[0])
		}
		if errs[1] != nil {
			t.Fatalf("iteration %d: ConfirmEnrollment raced against DeleteTOTP and failed: %v", i, errs[1])
		}
	}
}

// The tests below cover the behaviors this package commits to that the store
// interfaces do not require of every implementation, and so cannot live in
// storetest without holding conforming stores to more than their contract.

// TestConsumeChallengeRefusesAnExpiredChallenge pins the TTL the ChallengeStore
// interface asks implementations to apply ("roughly five minutes, matching the
// lifetime of a WebAuthn ceremony") but does not express in any method.
// storetest cannot check it: a store is conforming without it.
func TestConsumeChallengeRefusesAnExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	challenges := db.ChallengeStore()
	// The shortest lifetime the field accepts: the round trip through
	// PostgreSQL between saving and consuming is microseconds at best, so this
	// is reliably expired without the test sleeping for it.
	challenges.TTL = time.Nanosecond

	if err := challenges.SaveChallenge(ctx, "register:user-1", []byte("session-data")); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}
	if data, err := challenges.ConsumeChallenge(ctx, "register:user-1"); err == nil {
		t.Fatalf("ConsumeChallenge returned (%q, nil) for an expired challenge, want an error", data)
	}
	// The refused read still burned the row, the same direction ConsumeToken
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
// this package offers for challenges nobody ever finished, which the interface
// has no method for.
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
	if _, err := live.ConsumeChallenge(ctx, "abandoned"); !errors.Is(err, postgres.ErrChallengeNotFound) {
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

// TestNewAdoptsACallerOwnedHandle covers the other construction path, where the
// caller opens and configures the pool and applies the schema itself.
func TestNewAdoptsACallerOwnedHandle(t *testing.T) {
	ctx := context.Background()
	adopted := openDB(t)

	handle := adopted.SQL()
	// Migrating twice must be safe: the schema is written with IF NOT EXISTS
	// so an adopter running it on every boot is not punished for it.
	if err := postgres.Migrate(ctx, handle); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	db := postgres.New(handle)
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

// TestSearchPathDSN pins the DSN handling, which fails silently rather than
// loudly when it is wrong — the same lesson the SQLite store's FileDSN
// escaping carries. It needs no database, so it runs for every contributor.
func TestSearchPathDSN(t *testing.T) {
	t.Run("AddsTheParameterToABareURL", func(t *testing.T) {
		got, err := postgres.SearchPathDSN("postgres://user@host:5432/db", "tenant_7")
		if err != nil {
			t.Fatalf("SearchPathDSN: %v", err)
		}
		if got != "postgres://user@host:5432/db?search_path=tenant_7" {
			t.Fatalf("SearchPathDSN = %q", got)
		}
	})

	t.Run("KeepsTheParametersAlreadyThere", func(t *testing.T) {
		got, err := postgres.SearchPathDSN("postgres://user@host/db?sslmode=disable", "tenant_7")
		if err != nil {
			t.Fatalf("SearchPathDSN: %v", err)
		}
		// Concatenation would have produced a second "?" here and lost one of
		// the two parameters.
		if !strings.Contains(got, "sslmode=disable") || !strings.Contains(got, "search_path=tenant_7") {
			t.Fatalf("SearchPathDSN = %q, want both parameters kept", got)
		}
		if strings.Count(got, "?") != 1 {
			t.Fatalf("SearchPathDSN = %q, want exactly one %q", got, "?")
		}
	})

	t.Run("EscapesASchemaThatWouldTruncateTheDSN", func(t *testing.T) {
		got, err := postgres.SearchPathDSN("postgres://user@host/db?sslmode=disable", "a&b#c")
		if err != nil {
			t.Fatalf("SearchPathDSN: %v", err)
		}
		if !strings.Contains(got, "sslmode=disable") {
			t.Fatalf("SearchPathDSN = %q — an unescaped schema truncated the DSN", got)
		}
		if strings.Contains(got, "#") {
			t.Fatalf("SearchPathDSN = %q — an unescaped %q turned the rest of the DSN into a fragment", got, "#")
		}
	})

	t.Run("RefusesAKeywordValueDSNRatherThanManglingIt", func(t *testing.T) {
		if _, err := postgres.SearchPathDSN("host=localhost user=postgres", "tenant_7"); err == nil {
			t.Fatal("SearchPathDSN accepted a keyword/value DSN, which cannot carry a query string")
		}
	})

	t.Run("RefusesAnEmptySchema", func(t *testing.T) {
		if _, err := postgres.SearchPathDSN("postgres://user@host/db", ""); err == nil {
			t.Fatal("SearchPathDSN accepted an empty schema")
		}
	})

	// A DSN is a credential. url.Parse reports a failure by returning a
	// *url.Error that embeds the URL it failed on verbatim, so wrapping that
	// error with %w — which this function used to do — put the database
	// password into the message, and from there into whatever the caller
	// logged. The trigger is ordinary, not adversarial: a password
	// containing a bare '%' is not valid percent-escaping, and neither is a
	// stray control character.
	//
	// Both the whole password and the fragment a url.EscapeError would quote
	// back ("%ss") are asserted absent, because the obvious partial fix —
	// unwrapping to url.Error.Err — still leaks three characters of it.
	t.Run("NeverPutsTheDSNOrThePasswordInTheErrorMessage", func(t *testing.T) {
		for _, dsn := range []string{
			"postgres://app:p%ssword@db.internal:5432/sulis",
			"postgres://app:sup3rSecret@db.internal:5432/sulis\n",
		} {
			_, err := postgres.SearchPathDSN(dsn, "tenant_7")
			if err == nil {
				t.Fatalf("SearchPathDSN(%q) parsed, so this case no longer exercises the error path", dsn)
			}
			msg := err.Error()
			for _, secret := range []string{"p%ssword", "sup3rSecret", "%ss", "db.internal", dsn} {
				if strings.Contains(msg, secret) {
					t.Fatalf("SearchPathDSN error = %q, which contains %q — a DSN carries the database password and must never reach an error string", msg, secret)
				}
			}
		}
	})
}

// TestEveryMethodFailsClosedOnAnUnavailableDatabase walks every store method
// with the handle already closed and requires every method to report the
// failure.
//
// This is the property storetest cannot check, because it needs a store it can
// break on purpose: a method that swallowed a database error and returned nil
// would tell sulis a write landed when it did not — a revoked session that is
// still live, a consumed token that can be consumed again, a last-credential
// guard that reported success without deleting anything. Silence is the one
// unacceptable answer here, so the assertion is only that there IS an error,
// not which.
func TestEveryMethodFailsClosedOnAnUnavailableDatabase(t *testing.T) {
	ctx := context.Background()
	url := dsn(t)

	handle, err := sql.Open(postgres.DriverName, url)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db := postgres.New(handle)
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

// TestMigrateReportsAFailureRatherThanHalfApplyingIt covers the other side of
// Migrate: DDL in PostgreSQL is transactional, and this store leans on that.
func TestMigrateReportsAFailureRatherThanHalfApplyingIt(t *testing.T) {
	ctx := context.Background()
	url := dsn(t)

	handle, err := sql.Open(postgres.DriverName, url)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = handle.Close() }()

	// A search_path naming a schema that does not exist: the first CREATE
	// TABLE has nowhere to go.
	missing := uniqueSchema(t)
	scoped, err := postgres.SearchPathDSN(url, missing)
	if err != nil {
		t.Fatalf("SearchPathDSN: %v", err)
	}
	if _, err := postgres.Open(ctx, scoped); err == nil {
		t.Fatalf("Open succeeded against the missing schema %s, want an error", missing)
	}
}

// TestSchemaIsExported keeps the promise the package documentation makes to
// adopters running their own migration tool.
func TestSchemaIsExported(t *testing.T) {
	for _, table := range []string{
		"users", "sessions", "tokens", "passkey_credentials",
		"passkey_challenges", "totp_active", "totp_pending", "recovery_codes",
	} {
		if !strings.Contains(postgres.Schema, "CREATE TABLE IF NOT EXISTS "+table+" (") {
			t.Errorf("Schema does not create %s", table)
		}
	}
}
