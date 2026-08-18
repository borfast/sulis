package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/borfast/sulis"
)

// UserStore is the SQLite sulis.UserStore.
//
// The two requirements the interface places on a real implementation are both
// in the schema rather than in this file: the UNIQUE index on users.email is
// what makes two accounts racing to claim one address resolve to exactly one
// winner, and the version column is what lets UpdateUser express its
// compare-and-swap as a single statement. Neither can be moved up into Go
// code without reintroducing the race it exists to close.
type UserStore struct {
	db *sql.DB
}

var _ sulis.UserStore = (*UserStore)(nil)

// userColumns is the SELECT list every read below shares, in the order
// scanUser reads them.
const userColumns = `id, email, password_hash, created_at, updated_at, metadata,
	email_verified_at, pending_email, disabled_at, disabled_reason, locked_until,
	failed_login_attempts, version`

// CreateUser inserts user. An address another user already holds — or an ID
// already in use, which would lose an account if it silently overwrote —
// comes back from SQLite as a UNIQUE violation and is reported as
// sulis.ErrUserAlreadyExists.
//
// The row starts at version 0 whatever user.Version says: the version column
// is the store's, set on read and passed back unchanged to UpdateUser, and a
// new row has no prior write to be stale against.
func (s *UserStore) CreateUser(ctx context.Context, user *sulis.User) error {
	metadata, err := marshalJSON(user.Metadata)
	if err != nil {
		return err
	}

	const q = `INSERT INTO users (` + userColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
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
		return fmt.Errorf("sulis/sqlite: creating a user: %w", err)
	}
	return nil
}

// GetUserByID returns the user with the given ID, or sulis.ErrUserNotFound.
func (s *UserStore) GetUserByID(ctx context.Context, id string) (*sulis.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = ?`
	return scanUser(s.db.QueryRowContext(ctx, q, id))
}

// GetUserByEmail returns the user whose live address is email, or
// sulis.ErrUserNotFound. The comparison is the column's own, which is
// case-insensitive (see the schema): sulis normalizes an address to lowercase
// long before a store sees it, so this only ever differs from an exact match
// for a caller that skipped normalization, and there it fails safe.
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*sulis.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE email = ?`
	return scanUser(s.db.QueryRowContext(ctx, q, email))
}

// UpdateUser applies user only while the stored row's version still matches
// the one the caller read, and only if the address it carries is not another
// user's:
//
//	UPDATE users SET ..., version = version + 1
//	 WHERE id = ? AND version = ?
//
// Zero rows affected means either that no such user exists or that another
// writer already advanced the version, and the two are different errors to
// the caller, so a follow-up existence check inside the same transaction
// tells them apart: sulis.ErrUserNotFound or sulis.ErrConcurrentUpdate. A
// UNIQUE violation on the address is sulis.ErrUserAlreadyExists.
//
// The version predicate is checked first by construction. A write that is
// both stale and colliding therefore reports the staleness, which is the more
// useful of the two: the caller must re-read either way, and the collision it
// would have hit was computed from a row it no longer has.
func (s *UserStore) UpdateUser(ctx context.Context, user *sulis.User) error {
	metadata, err := marshalJSON(user.Metadata)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: updating a user: %w", err)
	}
	defer rollback(tx)

	const q = `UPDATE users SET
			email = ?, password_hash = ?, created_at = ?, updated_at = ?,
			metadata = ?, email_verified_at = ?, pending_email = ?,
			disabled_at = ?, disabled_reason = ?, locked_until = ?,
			failed_login_attempts = ?, version = version + 1
		WHERE id = ? AND version = ?`
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
		return fmt.Errorf("sulis/sqlite: updating a user: %w", err)
	}

	n, err := affected(res, "updating a user")
	if err != nil {
		return err
	}
	if n == 0 {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, user.ID).Scan(&exists)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return sulis.ErrUserNotFound
		case err != nil:
			return fmt.Errorf("sulis/sqlite: updating a user: %w", err)
		default:
			return sulis.ErrConcurrentUpdate
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/sqlite: committing a user update: %w", err)
	}
	return nil
}

// DeleteUser removes the user with the given ID. Deleting a user who is not
// there is not an error: the caller's intent is already satisfied.
func (s *UserStore) DeleteUser(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a user: %w", err)
	}
	return nil
}

// scanUser reads one row into a freshly built *sulis.User. Every pointer and
// map on the result is allocated here, which is how this store satisfies the
// interface's no-aliasing rule without doing anything about it.
func scanUser(row *sql.Row) (*sulis.User, error) {
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
		return nil, fmt.Errorf("sulis/sqlite: reading a user: %w", err)
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
