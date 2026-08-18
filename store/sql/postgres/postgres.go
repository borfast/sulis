// Package postgres is the PostgreSQL reference implementation of every store
// interface sulis defines: sulis.UserStore, sulis.SessionStore,
// sulis.TokenStore, passkey.Store, passkey.ChallengeStore, totp.Store, and
// recovery.Store.
//
// It lives in the same module as its SQLite sibling,
// github.com/borfast/sulis/store/sql, so that a SQL driver never enters the
// dependency graph of an application that brings its own store. Depending on
// this package is opting in to github.com/jackc/pgx/v5; depending on sulis is
// not.
//
// # What it is for
//
// memstore shows what the contracts mean with a mutex, and store/sql/sqlite
// shows what they mean in SQL on a database that has exactly one writer. This
// package shows what they mean on a database that does not: PostgreSQL runs
// every caller concurrently, so an atomicity requirement here has to be
// carried by a conditional statement, a row lock, or an advisory lock rather
// than by the engine happening to serialize. All three packages are held to
// the same bar — the whole storetest conformance suite, unmodified, passes
// against every one of them.
//
// # Concurrency
//
// The pool is a normal pool: several connections, all writing at once. That
// is the point of choosing PostgreSQL over the single-file SQLite store, and
// it is why three of the contracts need more than the statement their SQLite
// counterparts get.
//
// Most of them do not. PostgreSQL's READ COMMITTED isolation re-evaluates a
// blocked statement's WHERE clause against the row version the winner
// committed, which is exactly what a compare-and-swap needs: UpdateUser's
// "WHERE id = $1 AND version = $2", ConsumeToken's "WHERE used = false",
// ConsumeChallenge's and ConfirmEnrollment's "DELETE ... RETURNING", and
// DeleteSession's owner-scoped delete are all single statements whose losers
// see zero affected rows, without any lock this package takes itself.
//
// Three do not survive that treatment, because what they check is the ABSENCE
// or the COUNT of rows, and a snapshot from before the winner committed
// answers both questions wrongly:
//
//   - PasskeyStore.DeleteCredential's last-credential guard counts the user's
//     credentials. Two callers deleting two different rows of a two-credential
//     user both count 2, both pass, and the user is locked out.
//   - TOTPStore.EnrollPending refuses to write when an active credential
//     exists. A ConfirmEnrollment that has not committed yet is invisible, so
//     the enrollment lands anyway and silently replaces a working factor.
//   - TOTPStore.DeleteTOTP empties two tables. A ConfirmEnrollment can
//     interleave between them and resurrect an active credential the caller
//     believed it had removed.
//
// Each of those takes a transaction-scoped advisory lock keyed on the user
// (see lockUser) as its first statement, which makes every mutation of one
// user's credentials serial while leaving different users fully concurrent.
// It is the smallest thing that reproduces what SQLite's single writer gave
// the sibling package for free. Advisory locks are released when the
// transaction ends, whether it commits or rolls back, so a failed call cannot
// strand one.
//
// Every transaction here issues its lock or its first write immediately after
// BEGIN and holds no lock across a round trip it does not need, so the lock
// order is the same in every path and no two of these transactions can wait on
// each other.
//
// # Aliasing
//
// The interfaces forbid a store from sharing mutable state with its callers in
// either direction. A store that reconstructs rows from a database read gets
// this for free, and this one does: nothing a caller passes in is retained,
// and every value handed back is built from column values.
package postgres

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	// Registers the "pgx" driver name used by DriverName.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DriverName is the database/sql driver name github.com/jackc/pgx/v5/stdlib
// registers. Importing this package registers it, since the driver is
// imported here.
const DriverName = "pgx"

// Schema is the DDL every store in this package expects, exported so an
// adopter can hand it to their own migration tool instead of calling Migrate.
// It is written to be read: each constraint carries the contract it exists to
// enforce.
//
//go:embed schema.sql
var Schema string

// timeLayout is the fixed-width UTC layout every timestamp column is stored
// in.
//
// PostgreSQL has timestamptz and this package does not use it, which is worth
// justifying where someone will find it: timestamptz resolves to one
// microsecond and rounds anything finer away, while a Go time.Time carries
// nanoseconds and the session contract requires an exact round trip (storetest
// asserts ExpiresAt comes back Equal to an untruncated time.Now()). Nine
// fractional digits round-trip a time.Time exactly. Fixed width is the other
// half: the expiry sweeps (CleanExpired, DeleteExpiredTokens) compare with SQL
// "<", which on text is a byte comparison, and a layout that omitted trailing
// zeros in the fractional part would sort "…:05.5Z" before "…:05Z".
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// uniqueViolation is PostgreSQL's SQLSTATE for a write refused by a UNIQUE
// index or a primary key. Only this class is treated as "that value is taken";
// a NOT NULL or CHECK failure is also an integrity error and must not be
// reported to a caller as a collision.
const uniqueViolation = "23505"

// The advisory-lock classes. pg_advisory_xact_lock takes two 32-bit keys; the
// first namespaces the lock so a lock this package takes on a user's TOTP
// slots cannot collide with one it takes on the same user's passkeys, nor with
// whatever advisory locks the surrounding application uses. The values are
// arbitrary and only have to stay stable.
const (
	advisoryClassTOTP    int32 = 0x53554C31
	advisoryClassPasskey int32 = 0x53554C32
)

// DB owns a database handle and hands out the seven store implementations.
// All of them read and write through the same handle, so one DB is one
// database.
type DB struct {
	db *sql.DB
}

// SearchPathDSN returns dsn with its search_path runtime parameter set to
// schema, which is how one PostgreSQL database holds several independent
// copies of this schema (the conformance tests give every test function its
// own; a multi-tenant deployment might give every tenant one).
//
// The parameter is added through net/url rather than by concatenation,
// because concatenation is a silent bug rather than an error: a DSN that
// already carries "?sslmode=disable" would gain a second "?" and the driver
// would either reject it or drop everything after it, and a schema name
// containing "&" or "#" would truncate the DSN and connect somewhere other
// than where the caller asked. Both failures happen quietly, and one of them
// connects successfully to the wrong place.
//
// Only the URL form of a DSN can be rewritten this way. A keyword/value DSN
// ("host=… user=…") is returned as an error rather than mangled — appending a
// query string to one produces a DSN that parses into a different connection
// than the caller wrote.
func SearchPathDSN(dsn, schema string) (string, error) {
	if schema == "" {
		return "", errors.New("sulis/postgres: the search_path schema is empty")
	}

	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("sulis/postgres: parsing the DSN: %w", err)
	}
	switch parsed.Scheme {
	case "postgres", "postgresql":
	default:
		return "", fmt.Errorf("sulis/postgres: cannot set search_path on a %q DSN: only the postgres:// URL form can be rewritten safely", parsed.Scheme)
	}

	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// Open opens the database named by dsn, configures the connection pool, and
// applies Schema. dsn is anything pgx accepts: a postgres:// URL, a
// keyword/value string, or "" to take everything from the standard PG*
// environment variables.
//
// The pool is given modest defaults — enough connections for a small service,
// a bounded idle set, and a bounded lifetime so a connection cannot outlive a
// failover or a pooler restart. Tune them on the handle SQL returns, or build
// the handle yourself and use New.
//
// The caller owns the returned DB and must Close it.
func Open(ctx context.Context, dsn string) (*DB, error) {
	db, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: opening the database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sulis/postgres: connecting to the database: %w", err)
	}
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return New(db), nil
}

// New wraps an already-configured *sql.DB. The caller keeps ownership: New
// neither applies Schema (call Migrate, or run the DDL through your own
// migration tool) nor closes the handle, and DB.Close on a DB built this way
// closes the handle the caller passed in.
func New(db *sql.DB) *DB {
	return &DB{db: db}
}

// Migrate applies Schema. PostgreSQL's DDL is transactional, so every
// statement runs in one transaction and a database is either fully migrated or
// untouched. The DDL is written with IF NOT EXISTS throughout, so an adopter
// running it on every boot is not punished for it.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/postgres: beginning the migration: %w", err)
	}
	defer rollback(tx)

	if _, err := tx.ExecContext(ctx, Schema); err != nil {
		return fmt.Errorf("sulis/postgres: applying the schema: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/postgres: committing the migration: %w", err)
	}
	return nil
}

// SQL returns the underlying handle, for callers that need to run their own
// statements against the same database (a health check, a report, a migration
// of their own tables).
func (d *DB) SQL() *sql.DB { return d.db }

// Close closes the underlying handle.
func (d *DB) Close() error { return d.db.Close() }

// UserStore returns the sulis.UserStore backed by this database.
func (d *DB) UserStore() *UserStore { return &UserStore{db: d.db} }

// SessionStore returns the sulis.SessionStore backed by this database.
func (d *DB) SessionStore() *SessionStore { return &SessionStore{db: d.db} }

// TokenStore returns the sulis.TokenStore backed by this database.
func (d *DB) TokenStore() *TokenStore { return &TokenStore{db: d.db} }

// PasskeyStore returns the passkey.Store backed by this database.
func (d *DB) PasskeyStore() *PasskeyStore { return &PasskeyStore{db: d.db} }

// ChallengeStore returns the passkey.ChallengeStore backed by this database,
// with the default challenge lifetime. Set its TTL field to change it.
func (d *DB) ChallengeStore() *ChallengeStore { return &ChallengeStore{db: d.db} }

// TOTPStore returns the totp.Store backed by this database.
func (d *DB) TOTPStore() *TOTPStore { return &TOTPStore{db: d.db} }

// RecoveryStore returns the recovery.Store backed by this database.
func (d *DB) RecoveryStore() *RecoveryStore { return &RecoveryStore{db: d.db} }

// isUniqueViolation reports whether err is PostgreSQL refusing a write that
// would duplicate a UNIQUE index or a primary key.
//
// Which index was violated is deliberately not inspected — every UNIQUE
// constraint in this schema that a caller can collide with means exactly one
// thing to the interface being implemented, and the callers below map it
// there.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}

// lockUser takes the transaction-scoped advisory lock for one user within one
// class, and must be the first statement of any transaction that takes it, so
// that every path acquires locks in the same order.
//
// This is what stands in for SQLite's single writer in the three places a
// contract asks about the absence or the count of rows rather than about one
// row's contents — see the package documentation. PostgreSQL releases the lock
// when the transaction ends either way, so a rolled-back call cannot strand
// one, and a caller waiting on it blocks rather than reading a stale answer.
//
// The key is a 32-bit hash of the user ID, so two user IDs can collide and
// serialize against each other. That costs a little throughput on a collision
// and nothing else: the lock is only ever used to make one user's writes
// serial, never to decide anything.
func lockUser(ctx context.Context, tx *sql.Tx, class int32, userID string) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, class, advisoryKey(userID)); err != nil {
		return fmt.Errorf("sulis/postgres: locking the user's rows: %w", err)
	}
	return nil
}

// advisoryKey hashes a user ID into the 32-bit key pg_advisory_xact_lock
// takes. The conversion deliberately wraps: this is a lock key, not a number,
// and every bit of the hash is as good as any other.
func advisoryKey(userID string) int32 {
	h := fnv.New32a()
	// hash.Hash.Write never returns an error.
	_, _ = h.Write([]byte(userID))
	return int32(h.Sum32()) // #nosec G115 -- a lock key, not a quantity; wrapping is intended
}

// formatTime renders t for storage. Converting to UTC first is what keeps the
// column fixed-width: the layout has no zone element, so a caller's local
// offset would otherwise be silently dropped rather than applied.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// parseTime reads a stored timestamp back.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sulis/postgres: parsing the stored timestamp %q: %w", s, err)
	}
	return t, nil
}

// nullableTime renders an optional timestamp for storage: a nil pointer
// becomes SQL NULL. The nil case matters as much as the other one —
// TouchSession clearing IdleExpiresAt back to nil must write NULL rather than
// leave a stale deadline enforcing itself after idle expiry was turned off.
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

// scanNullableTime reads an optional timestamp back, returning a pointer to a
// fresh time.Time so nothing is shared with any other row or caller.
func scanNullableTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil
	}
	t, err := parseTime(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// marshalJSON renders a value for storage in a jsonb column, mapping the empty
// case to SQL NULL so an absent map and an empty one read back the same way.
func marshalJSON(v any) (any, error) {
	switch typed := v.(type) {
	case map[string]any:
		if typed == nil {
			return nil, nil
		}
	case nil:
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: encoding a JSON column: %w", err)
	}
	return string(b), nil
}

// unmarshalJSON reads a jsonb column back into dst, leaving dst alone when the
// column is NULL.
func unmarshalJSON(s sql.NullString, dst any) error {
	if !s.Valid || s.String == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(s.String), dst); err != nil {
		return fmt.Errorf("sulis/postgres: decoding a JSON column: %w", err)
	}
	return nil
}

// rollback discards tx, ignoring the error a commit already made moot.
// Deferred at the top of every transaction here, so an early return can never
// leave one open — and, since every lock this package takes is transaction
// scoped, can never leave one held either.
func rollback(tx *sql.Tx) {
	_ = tx.Rollback()
}

// affected reports how many rows a statement changed, turning the driver's
// error into one naming the operation.
func affected(res sql.Result, op string) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sulis/postgres: %s: reading the affected row count: %w", op, err)
	}
	return n, nil
}

// scanner is what *sql.Row and *sql.Rows have in common, so one scan helper
// serves both the single-row reads and the list queries.
type scanner interface {
	Scan(dest ...any) error
}
