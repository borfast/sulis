package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/borfast/sulis"
)

// UserStore is the PostgreSQL sulis.UserStore.
//
// The two requirements the interface places on a real implementation are both
// in the schema rather than in this file: the UNIQUE index on lower(email) is
// what makes two accounts racing to claim one address resolve to exactly one
// winner, and the version column is what lets UpdateUser express its
// compare-and-swap as a single statement. Neither can be moved up into Go code
// without reintroducing the race it exists to close.
//
// Nothing here takes a lock this package chose. Both races are between two
// writers of ONE row (or of one index entry), and PostgreSQL's READ COMMITTED
// isolation already makes the loser of such a race re-evaluate its WHERE
// clause against what the winner committed — so the loser's UPDATE matches
// zero rows, or its INSERT is refused by the index, without any help.
type UserStore struct {
	db *sql.DB
}

var _ sulis.UserStore = (*UserStore)(nil)

// userColumns is the SELECT list every read below shares, in the order
// scanUser reads them.
const userColumns = `id, email, password_hash, created_at, updated_at, metadata,
	email_verified_at, pending_email, disabled_at, disabled_reason, locked_until,
	failed_login_attempts, version`

// CreateUser inserts user. An address another user already holds — case
// insensitively, see the schema — or an ID already in use, which would lose an
// account if it silently overwrote, comes back from PostgreSQL as SQLSTATE
// 23505 and is reported as sulis.ErrUserAlreadyExists.
//
// The row starts at version 0 whatever user.Version says: the version column is
// the store's, set on read and passed back unchanged to UpdateUser, and a new
// row has no prior write to be stale against.
func (s *UserStore) CreateUser(ctx context.Context, user *sulis.User) error {
	metadata, err := marshalJSON(user.Metadata)
	if err != nil {
		return err
	}

	const q = `INSERT INTO users (` + userColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 0)`
	_, err = s.db.ExecContext(ctx, q,
		user.ID, user.Email, user.PasswordHash,
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt), metadata,
		nullableTime(user.EmailVerifiedAt), user.PendingEmail,
		nullableTime(user.DisabledAt), user.DisabledReason,
		nullableTime(user.LockedUntil), user.FailedLoginAttempts,
	)
	if isUniqueViolation(err) {
		return sulis.ErrUserAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("sulis/postgres: creating a user: %w", err)
	}
	return nil
}

// GetUserByID returns the user with the given ID, or sulis.ErrUserNotFound.
func (s *UserStore) GetUserByID(ctx context.Context, id string) (*sulis.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	return scanUser(s.db.QueryRowContext(ctx, q, id))
}

// GetUserByEmail returns the user whose live address is email, or
// sulis.ErrUserNotFound.
//
// The comparison is lower(email) = lower($1), which is both the
// case-insensitive match the SQLite sibling's COLLATE NOCASE column gives and
// the exact expression the unique index is built on — so this uses the index
// rather than sequentially scanning the table, which a plain "email = $1"
// against a functionally-indexed column would quietly do. sulis normalizes an
// address to lowercase long before a store sees it, so this only ever differs
// from an exact match for a caller that skipped normalization, and there it
// fails safe.
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*sulis.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE lower(email) = lower($1)`
	return scanUser(s.db.QueryRowContext(ctx, q, email))
}

// UpdateUser applies user only while the stored row's version still matches the
// one the caller read, and only if the address it carries is not another
// user's:
//
//	UPDATE users SET ..., version = version + 1
//	 WHERE id = $1 AND version = $2
//
// Zero rows affected means either that no such user exists or that another
// writer already advanced the version, and the two are different errors to the
// caller, so a follow-up existence check inside the same transaction tells them
// apart: sulis.ErrUserNotFound or sulis.ErrConcurrentUpdate. A unique violation
// on the address is sulis.ErrUserAlreadyExists.
//
// Under READ COMMITTED a second writer blocks on the row the first is updating
// and then re-evaluates this WHERE clause against the committed result, so the
// version predicate is what rejects it — not the order the two arrived in.
//
// The version predicate is checked first by construction. A write that is both
// stale and colliding therefore reports the staleness, which is the more useful
// of the two: the caller must re-read either way, and the collision it would
// have hit was computed from a row it no longer has.
func (s *UserStore) UpdateUser(ctx context.Context, user *sulis.User) error {
	metadata, err := marshalJSON(user.Metadata)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/postgres: updating a user: %w", err)
	}
	defer rollback(tx)

	const q = `UPDATE users SET
			email = $1, password_hash = $2, created_at = $3, updated_at = $4,
			metadata = $5, email_verified_at = $6, pending_email = $7,
			disabled_at = $8, disabled_reason = $9, locked_until = $10,
			failed_login_attempts = $11, version = version + 1
		WHERE id = $12 AND version = $13`
	res, err := tx.ExecContext(ctx, q,
		user.Email, user.PasswordHash,
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt), metadata,
		nullableTime(user.EmailVerifiedAt), user.PendingEmail,
		nullableTime(user.DisabledAt), user.DisabledReason,
		nullableTime(user.LockedUntil), user.FailedLoginAttempts,
		user.ID, int64(user.Version), // #nosec G115 -- version starts at 0 and only ever advances by one per write; 2^63 writes to one user row is not a timeline
	)
	if isUniqueViolation(err) {
		return sulis.ErrUserAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("sulis/postgres: updating a user: %w", err)
	}

	n, err := affected(res, "updating a user")
	if err != nil {
		return err
	}
	if n == 0 {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = $1`, user.ID).Scan(&exists)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return sulis.ErrUserNotFound
		case err != nil:
			return fmt.Errorf("sulis/postgres: updating a user: %w", err)
		default:
			return sulis.ErrConcurrentUpdate
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/postgres: committing a user update: %w", err)
	}
	return nil
}

// DeleteUser removes the user with the given ID. Deleting a user who is not
// there is not an error: the caller's intent is already satisfied.
func (s *UserStore) DeleteUser(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return fmt.Errorf("sulis/postgres: deleting a user: %w", err)
	}
	return nil
}

// scanUser reads one row into a freshly built *sulis.User. Every pointer and
// map on the result is allocated here, which is how this store satisfies the
// interface's no-aliasing rule without doing anything about it.
func scanUser(row scanner) (*sulis.User, error) {
	var (
		u                                        sulis.User
		createdAt, updatedAt                     string
		metadata                                 sql.NullString
		emailVerifiedAt, disabledAt, lockedUntil sql.NullString
		version                                  int64
	)
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &createdAt, &updatedAt, &metadata,
		&emailVerifiedAt, &u.PendingEmail, &disabledAt, &u.DisabledReason,
		&lockedUntil, &u.FailedLoginAttempts, &version,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sulis.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: reading a user: %w", err)
	}

	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(metadata, &u.Metadata); err != nil {
		return nil, err
	}
	if u.EmailVerifiedAt, err = scanNullableTime(emailVerifiedAt); err != nil {
		return nil, err
	}
	if u.DisabledAt, err = scanNullableTime(disabledAt); err != nil {
		return nil, err
	}
	if u.LockedUntil, err = scanNullableTime(lockedUntil); err != nil {
		return nil, err
	}
	u.Version = uint64(version) // #nosec G115 -- the column is written as 0 or version+1 and is never negative
	return &u, nil
}
