package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/borfast/sulis/totp"
)

// TOTPStore is the PostgreSQL totp.Store.
//
// The active and pending slots are two tables, both keyed by user_id, so "at
// most one of each per user" is a primary key rather than a convention. Every
// transition between them is expressed the same way its SQLite sibling
// expresses it — an INSERT ... SELECT ... WHERE NOT EXISTS upsert for
// EnrollPending, a DELETE ... RETURNING feeding an upsert for
// ConfirmEnrollment, a conditional upsert that refuses to lower the counter for
// SaveTOTP, two deletes in one transaction for DeleteTOTP.
//
// Every mutation here also opens by taking the user's advisory lock, which the
// SQLite store did not need because SQLite has one writer. Two of these
// operations ask about the ABSENCE of a row (EnrollPending: "is there an active
// credential?") or span two tables (DeleteTOTP, ConfirmEnrollment), and a
// snapshot taken before a concurrent writer committed answers both wrongly:
// an enrollment would silently replace a factor a racing confirmation had just
// promoted, and a deletion would leave behind an active credential a racing
// confirmation slipped in between its two DELETEs. The lock makes one user's
// TOTP writes serial and leaves different users concurrent. Reads take no lock:
// they answer about one row, at one instant, which is all their contract
// promises.
type TOTPStore struct {
	db *sql.DB
}

var _ totp.Store = (*TOTPStore)(nil)

// ErrTOTPCounterRegressed is returned by TOTPStore.SaveTOTP when a save would
// lower LastUsedCounter for the active credential with the same ID. totp.Store
// requires such a save to be rejected but does not name the error; failing
// closed is the point, since a counter that can regress is a code that can be
// replayed.
var ErrTOTPCounterRegressed = errors.New("sulis/postgres: TOTP counter would regress")

// GetActiveTOTP returns userID's active (verified) credential — the one Validate
// checks codes against — or totp.ErrTOTPNotEnrolled, whether or not a pending
// enrollment exists.
func (s *TOTPStore) GetActiveTOTP(ctx context.Context, userID string) (*totp.Credential, error) {
	const q = `SELECT id, user_id, secret, last_used_counter, created_at
		FROM totp_active WHERE user_id = $1`

	var (
		cred      totp.Credential
		counter   int64
		createdAt string
	)
	err := s.db.QueryRowContext(ctx, q, userID).
		Scan(&cred.ID, &cred.UserID, &cred.Secret, &counter, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, totp.ErrTOTPNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: reading an active TOTP credential: %w", err)
	}
	if cred.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	cred.LastUsedCounter = uint64(counter) // #nosec G115 -- written from a time-step counter, never negative
	cred.Verified = true
	return &cred, nil
}

// GetPendingTOTP returns userID's pending (unverified) enrollment awaiting
// ConfirmEnrollment, or totp.ErrTOTPNotEnrolled.
func (s *TOTPStore) GetPendingTOTP(ctx context.Context, userID string) (*totp.Credential, error) {
	const q = `SELECT id, user_id, secret, created_at FROM totp_pending WHERE user_id = $1`

	var (
		cred      totp.Credential
		createdAt string
	)
	err := s.db.QueryRowContext(ctx, q, userID).
		Scan(&cred.ID, &cred.UserID, &cred.Secret, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, totp.ErrTOTPNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: reading a pending TOTP enrollment: %w", err)
	}
	if cred.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	cred.Verified = false
	return &cred, nil
}

// EnrollPending stores cred as userID's pending enrollment, but only if the user
// has no active credential:
//
//	INSERT INTO totp_pending (user_id, id, secret, created_at)
//	SELECT $1, $2, $3, $4
//	 WHERE NOT EXISTS (SELECT 1 FROM totp_active WHERE user_id = $1)
//	    ON CONFLICT (user_id) DO UPDATE SET ...
//
// The guard is the statement's own WHERE clause, so it cannot be split from the
// write. On PostgreSQL that alone is not sufficient, because NOT EXISTS is
// answered from a snapshot: a ConfirmEnrollment that has already inserted into
// totp_active but not yet committed is invisible, so the check would pass and
// this write would land undetected, silently replacing a factor the user relies
// on. The user's advisory lock closes that window — a racing confirmation either
// has committed (and NOT EXISTS sees it) or has not started (and this call
// commits first, so the confirmation's own DELETE ... RETURNING finds a
// different pending row and refuses).
//
// Zero rows affected therefore means an active credential exists —
// totp.ErrTOTPAlreadyEnrolled, which Service.Enroll surfaces unchanged.
//
// Any pending enrollment already on file is superseded either way: at most one
// exists per user, and an unconfirmed one has nothing worth protecting.
func (s *TOTPStore) EnrollPending(ctx context.Context, cred *totp.Credential) error {
	const q = `INSERT INTO totp_pending (user_id, id, secret, created_at)
		SELECT $1, $2, $3, $4
		 WHERE NOT EXISTS (SELECT 1 FROM totp_active WHERE user_id = $1)
		ON CONFLICT (user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret, created_at = excluded.created_at`

	n, err := s.lockedExec(ctx, cred.UserID, "enrolling a pending TOTP credential", q,
		cred.UserID, cred.ID, cred.Secret, formatTime(cred.CreatedAt))
	if err != nil {
		return err
	}
	if n == 0 {
		return totp.ErrTOTPAlreadyEnrolled
	}
	return nil
}

// ReplacePending is EnrollPending without the active-credential guard: it stores
// cred as userID's pending enrollment whatever else is on file, and leaves any
// active credential completely alone, so codes keep validating against the old
// factor until a later ConfirmEnrollment promotes this one.
//
// It takes the user's lock all the same. It has no guard of its own to protect,
// but DeleteTOTP's promise ("the user ends up with nothing") is only worth
// anything if no other write to either slot can land between its two deletes.
func (s *TOTPStore) ReplacePending(ctx context.Context, cred *totp.Credential) error {
	const q = `INSERT INTO totp_pending (user_id, id, secret, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret, created_at = excluded.created_at`

	_, err := s.lockedExec(ctx, cred.UserID, "replacing a pending TOTP enrollment", q,
		cred.UserID, cred.ID, cred.Secret, formatTime(cred.CreatedAt))
	return err
}

// ConfirmEnrollment promotes userID's pending enrollment to active, but only
// while it is still the one named by pendingID — the enrollment whose secret the
// caller just matched a code against.
//
// The comparison and the promotion are one transaction whose first write is the
// DELETE that consumes the pending row:
//
//	DELETE FROM totp_pending WHERE user_id = $1 AND id = $2 RETURNING ...
//
// Returning no row means pendingID no longer matches — already promoted,
// superseded by a racing enrollment, or never there — so nothing is touched and
// totp.ErrTOTPNotEnrolled comes back, which the caller treats exactly like
// "nothing to confirm".
//
// counter is the time step the code was matched at. When an active credential
// already exists (this is a replacement, not a first enrollment) the promoted
// credential keeps whichever counter is higher, so swapping factors can never
// roll the user's replay-protection clock backwards.
func (s *TOTPStore) ConfirmEnrollment(ctx context.Context, userID, pendingID string, counter uint64) (*totp.Credential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: confirming a TOTP enrollment: %w", err)
	}
	defer rollback(tx)

	if err := lockUser(ctx, tx, advisoryClassTOTP, userID); err != nil {
		return nil, err
	}

	const consume = `DELETE FROM totp_pending WHERE user_id = $1 AND id = $2
		RETURNING id, secret, created_at`

	var (
		promoted  totp.Credential
		createdAt string
	)
	err = tx.QueryRowContext(ctx, consume, userID, pendingID).
		Scan(&promoted.ID, &promoted.Secret, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, totp.ErrTOTPNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: confirming a TOTP enrollment: %w", err)
	}
	if promoted.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}

	var prior int64
	err = tx.QueryRowContext(ctx,
		`SELECT last_used_counter FROM totp_active WHERE user_id = $1`, userID).Scan(&prior)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("sulis/postgres: reading the prior TOTP counter: %w", err)
	}
	if prior > 0 && uint64(prior) > counter {
		counter = uint64(prior)
	}

	const promote = `INSERT INTO totp_active (user_id, id, secret, last_used_counter, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret,
			last_used_counter = excluded.last_used_counter,
			created_at = excluded.created_at`
	// #nosec G115 -- a TOTP time-step counter is unix-seconds/period; it does
	// not reach 2^63 in any timeline this code outlives.
	if _, err := tx.ExecContext(ctx, promote,
		userID, promoted.ID, promoted.Secret, int64(counter), formatTime(promoted.CreatedAt),
	); err != nil {
		return nil, fmt.Errorf("sulis/postgres: promoting a TOTP enrollment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sulis/postgres: committing a TOTP promotion: %w", err)
	}

	promoted.UserID = userID
	promoted.Verified = true
	promoted.LastUsedCounter = counter
	return &promoted, nil
}

// SaveTOTP persists an update to an existing active credential — in practice
// Validate's post-check LastUsedCounter bump — as a single conditional upsert:
//
//	INSERT INTO totp_active (...) VALUES (...)
//	    ON CONFLICT (user_id) DO UPDATE SET ...
//	 WHERE totp_active.id <> excluded.id
//	    OR excluded.last_used_counter >= totp_active.last_used_counter
//
// The WHERE on DO UPDATE is the monotonicity guard: a save that would lower the
// counter for the active credential with the same ID matches nothing, changes
// nothing, and is reported as ErrTOTPCounterRegressed rather than applied. Of
// two racing validations only one advances the clock, and the loser cannot
// rewind it.
//
// It runs under the user's lock like every other write here. PostgreSQL would
// very likely be enough on its own — ON CONFLICT DO UPDATE re-checks its WHERE
// against the row version a concurrent writer committed — but a replay-counter
// guard is the last place to rest on "very likely", and the lock is already the
// package's answer everywhere else.
func (s *TOTPStore) SaveTOTP(ctx context.Context, cred *totp.Credential) error {
	const q = `INSERT INTO totp_active (user_id, id, secret, last_used_counter, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret,
			last_used_counter = excluded.last_used_counter,
			created_at = excluded.created_at
		 WHERE totp_active.id <> excluded.id
		    OR excluded.last_used_counter >= totp_active.last_used_counter`

	// #nosec G115 -- see ConfirmEnrollment: the counter is a time step.
	n, err := s.lockedExec(ctx, cred.UserID, "saving a TOTP credential", q,
		cred.UserID, cred.ID, cred.Secret, int64(cred.LastUsedCounter), formatTime(cred.CreatedAt))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTOTPCounterRegressed
	}
	return nil
}

// DeleteTOTP removes userID's active credential and any pending enrollment, both
// inside one transaction and under the user's lock. Removing them one after the
// other would let a concurrent ConfirmEnrollment promotion land in the gap,
// leaving the just-promoted credential behind as an active factor the caller
// believed it had removed entirely — and on PostgreSQL the transaction alone
// does not close that gap, because the promotion writes a row this transaction's
// DELETE never saw and so never locked. Removing nothing is not an error.
func (s *TOTPStore) DeleteTOTP(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/postgres: deleting TOTP credentials: %w", err)
	}
	defer rollback(tx)

	if err := lockUser(ctx, tx, advisoryClassTOTP, userID); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_active WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("sulis/postgres: deleting an active TOTP credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_pending WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("sulis/postgres: deleting a pending TOTP enrollment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/postgres: committing a TOTP deletion: %w", err)
	}
	return nil
}

// lockedExec runs one statement in a transaction that opens by taking userID's
// TOTP lock, and reports how many rows it affected. The three single-statement
// mutations above all need the lock and nothing else, and this keeps the shape
// in one place rather than repeated three times.
func (s *TOTPStore) lockedExec(ctx context.Context, userID, op, query string, args ...any) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sulis/postgres: %s: %w", op, err)
	}
	defer rollback(tx)

	if err := lockUser(ctx, tx, advisoryClassTOTP, userID); err != nil {
		return 0, err
	}

	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sulis/postgres: %s: %w", op, err)
	}
	n, err := affected(res, op)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sulis/postgres: committing while %s: %w", op, err)
	}
	return n, nil
}
