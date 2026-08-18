// Package sqlite is the SQLite reference implementation of every store
// interface sulis defines: sulis.UserStore, sulis.SessionStore,
// sulis.TokenStore, passkey.Store, passkey.ChallengeStore, totp.Store, and
// recovery.Store.
//
// It lives in its own module, github.com/borfast/sulis/store/sql, so that a
// SQL driver never enters the dependency graph of an application that brings
// its own store. Depending on this package is opting in to
// modernc.org/sqlite; depending on sulis is not.
//
// # What it is for
//
// memstore shows what the contracts mean with a mutex. This package shows
// what they mean in SQL, which is where most adopters will actually have to
// satisfy them: every atomicity requirement the interfaces document is
// expressed here as one conditional statement or one transaction, and the
// comment on each method names which. Both packages are held to the same bar
// — the whole storetest conformance suite, unmodified, passes against both.
//
// It is also a usable store. modernc.org/sqlite is pure Go, so this builds
// and runs without cgo, and a single-file SQLite database is a reasonable
// answer for a single-process application. It is not an answer for several
// application processes sharing one database file over a network filesystem;
// see T602's Postgres store for that shape.
//
// # Concurrency
//
// Open configures the pool with exactly one connection. SQLite allows one
// writer at a time whatever the pool says, so a second connection buys
// concurrent reads and costs SQLITE_BUSY handling on every write path; one
// connection makes every statement and every transaction here serial by
// construction, which is the honest way to satisfy contracts whose entire
// point is that a check and a mutation cannot be split. The cost is
// throughput, and it is stated rather than hidden: this store serializes.
//
// Every multi-statement transaction in this package issues a write as its
// first statement, so SQLite takes the write lock at BEGIN-plus-one rather
// than trying to upgrade a read transaction later — the one deadlock shape
// busy_timeout famously does not rescue you from. That property is worth
// preserving if you adapt this code to a pool with more connections.
//
// # Aliasing
//
// The interfaces forbid a store from sharing mutable state with its callers
// in either direction. A store that reconstructs rows from a database read
// gets this for free, and this one does: nothing a caller passes in is
// retained, and every value handed back is built from column values.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// DriverName is the database/sql driver name modernc.org/sqlite registers.
// Importing this package registers it, since the driver is imported here.
const DriverName = "sqlite"

// Schema is the DDL every store in this package expects, exported so an
// adopter can hand it to their own migration tool instead of calling
// Migrate. It is written to be read: each constraint carries the contract it
// exists to enforce.
//
//go:embed schema.sql
var Schema string

// timeLayout is the fixed-width UTC layout every timestamp column is stored
// in. Fixed width is the point: the expiry sweeps (CleanExpired,
// DeleteExpiredTokens) compare timestamps with SQL "<", which on TEXT is a
// byte comparison, and a layout that omitted trailing zeros in the fractional
// part would sort "…:05.5Z" before "…:05Z". Nine fractional digits round-trip
// a time.Time without losing precision, which the session contract needs:
// storetest asserts that ExpiresAt comes back Equal to what went in.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// DB owns a database handle and hands out the seven store implementations.
// All of them read and write through the same handle, so one DB is one
// database.
type DB struct {
	db *sql.DB
}

// MemoryDSN returns a DSN for a private in-memory database, useful for tests
// and examples. The database exists only as long as the connection does,
// which is why Open pins the pool to a single connection that is never
// retired.
func MemoryDSN() string {
	return ":memory:"
}

// FileDSN returns a DSN for the database file at path, with the pragmas a
// durable single-process store wants: WAL journaling (readers do not block
// the writer), synchronous=NORMAL (the WAL-safe setting — a crash can lose
// the last committed transaction but cannot corrupt the database), and a
// 10-second busy timeout as a backstop for another process holding the file.
//
// The path is percent-escaped into the URI. Concatenating it raw would be a
// quiet data-loss bug rather than an error: a path containing "?" or "#"
// terminates the URI early, and SQLite would happily create and use a
// different file than the one asked for.
func FileDSN(path string) string {
	q := url.Values{}
	q.Set("_busy_timeout", "10000")
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "NORMAL")

	// Opaque rather than Path: an empty authority ("file:///x") is legal but
	// a relative path has no authority form at all, and Opaque renders both
	// as SQLite's own documented "file:" + path shape.
	dsn := url.URL{
		Scheme:   "file",
		Opaque:   (&url.URL{Path: path}).EscapedPath(),
		RawQuery: q.Encode(),
	}
	return dsn.String()
}

// Open opens the database named by dsn, configures the connection pool, and
// applies Schema. Build dsn with FileDSN or MemoryDSN, or write your own.
//
// Neither error below names dsn, matching the Postgres sibling: a DSN never
// reaches an error string, not even wrapped. A SQLite DSN carries a file
// path rather than a password, but the rule is absolute on purpose — a path
// is deployment topology, an encrypted build's key pragma would be a
// credential outright, and a rule applied case by case is a rule somebody
// eventually decides wrong. Nothing is lost: the caller passed dsn in and
// still has it.
//
// The pool is pinned to a single connection, never retired: see the package
// documentation for why one connection is the honest configuration for a
// store whose contracts are about atomicity, and note that an in-memory
// database would not survive its connection being recycled anyway.
//
// The caller owns the returned DB and must Close it.
func Open(ctx context.Context, dsn string) (*DB, error) {
	db, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("sulis/sqlite: opening the database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sulis/sqlite: connecting to the database: %w", err)
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
//
// Configure the pool with SetMaxOpenConns(1) unless you have read the
// package documentation's concurrency section and decided otherwise.
func New(db *sql.DB) *DB {
	return &DB{db: db}
}

// Migrate applies Schema. Every statement runs in one transaction, so a
// database is either fully migrated or untouched.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: beginning the migration: %w", err)
	}
	defer rollback(tx)

	if _, err := tx.ExecContext(ctx, Schema); err != nil {
		return fmt.Errorf("sulis/sqlite: applying the schema: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/sqlite: committing the migration: %w", err)
	}
	return nil
}

// SQL returns the underlying handle, for callers that need to run their own
// statements against the same database (a health check, a report, a
// migration of their own tables).
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

// isUniqueViolation reports whether err is SQLite refusing a write that would
// duplicate a UNIQUE index or a primary key.
//
// The two extended result codes are checked, not the primary SQLITE_CONSTRAINT
// (19) they share: a CHECK or NOT NULL failure is also a constraint failure
// and must not be reported to a caller as "that address is taken". Which
// index was violated is deliberately not inspected — every UNIQUE constraint
// in this schema that a caller can collide with means exactly one thing to
// the interface being implemented, and the callers below map it there.
func isUniqueViolation(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	switch serr.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	default:
		return false
	}
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
		return time.Time{}, fmt.Errorf("sulis/sqlite: parsing the stored timestamp %q: %w", s, err)
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

// marshalJSON renders a value for storage in a JSON text column, mapping the
// empty case to SQL NULL so an absent map and an empty one read back the same
// way.
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
		return nil, fmt.Errorf("sulis/sqlite: encoding a JSON column: %w", err)
	}
	return string(b), nil
}

// unmarshalJSON reads a JSON text column back into dst, leaving dst alone
// when the column is NULL.
func unmarshalJSON(s sql.NullString, dst any) error {
	if !s.Valid || s.String == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(s.String), dst); err != nil {
		return fmt.Errorf("sulis/sqlite: decoding a JSON column: %w", err)
	}
	return nil
}

// boolToInt renders a bool for an INTEGER column.
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// rollback discards tx, ignoring the error a commit already made moot.
// Deferred at the top of every transaction here, so an early return can never
// leave one open.
func rollback(tx *sql.Tx) {
	_ = tx.Rollback()
}

// affected reports how many rows a statement changed, turning the driver's
// error into one naming the operation.
func affected(res sql.Result, op string) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sulis/sqlite: %s: reading the affected row count: %w", op, err)
	}
	return n, nil
}
