package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/borfast/sulis/totp"
)

// TOTPStore is the SQLite totp.Store.
//
// The active and pending slots are two tables, both keyed by user_id, so "at
// most one of each per user" is a primary key rather than a convention. Every
// transition between them is one statement or one transaction:
//
//   - EnrollPending is an INSERT ... SELECT ... WHERE NOT EXISTS upsert, so
//     the no-active-credential check and the write cannot be split.
//   - ConfirmEnrollment is a DELETE ... RETURNING on the pending row feeding
//     an upsert of the active one, in a transaction — the compare-and-swap
//     that closes the clobber race.
//   - SaveTOTP is a conditional upsert that refuses to lower the counter.
//   - DeleteTOTP empties both slots in one transaction, so no promotion can
//     land between the two removals and resurrect a factor the caller
//     believed it had removed.
type TOTPStore struct {
	db *sql.DB
}

var _ totp.Store = (*TOTPStore)(nil)

// ErrTOTPCounterRegressed is returned by TOTPStore.SaveTOTP when a save would
// lower LastUsedCounter for the active credential with the same ID. totp.Store
// requires such a save to be rejected but does not name the error; failing
// closed is the point, since a counter that can regress is a code that can be
// replayed.
var ErrTOTPCounterRegressed = errors.New("sulis/sqlite: TOTP counter would regress")

// GetActiveTOTP returns userID's active (verified) credential — the one
// Validate checks codes against — or totp.ErrTOTPNotEnrolled, whether or not
// a pending enrollment exists.
func (s *TOTPStore) GetActiveTOTP(ctx context.Context, userID string) (*totp.Credential, error) {
	const q = `SELECT id, user_id, secret, last_used_counter, created_at
		FROM totp_active WHERE user_id = ?`

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
		return nil, fmt.Errorf("sulis/sqlite: reading an active TOTP credential: %w", err)
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
	const q = `SELECT id, user_id, secret, created_at FROM totp_pending WHERE user_id = ?`

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
		return nil, fmt.Errorf("sulis/sqlite: reading a pending TOTP enrollment: %w", err)
	}
	if cred.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	cred.Verified = false
	return &cred, nil
}

// EnrollPending stores cred as userID's pending enrollment, but only if the
// user has no active credential:
//
//	INSERT INTO totp_pending (user_id, id, secret, created_at)
//	SELECT ?, ?, ?, ?
//	 WHERE NOT EXISTS (SELECT 1 FROM totp_active WHERE user_id = ?)
//	    ON CONFLICT(user_id) DO UPDATE SET ...
//
// The guard is the statement's own WHERE clause, so it cannot be split from
// the write: a ConfirmEnrollment landing between a separate check and a
// separate write would promote some other enrollment to active and this write
// would then land undetected, silently replacing a factor the user relies on.
// Zero rows affected therefore means an active credential exists —
// totp.ErrTOTPAlreadyEnrolled, which Service.Enroll surfaces unchanged.
//
// Any pending enrollment already on file is superseded either way: at most
// one exists per user, and an unconfirmed one has nothing worth protecting.
func (s *TOTPStore) EnrollPending(ctx context.Context, cred *totp.Credential) error {
	const q = `INSERT INTO totp_pending (user_id, id, secret, created_at)
		SELECT ?, ?, ?, ?
		 WHERE NOT EXISTS (SELECT 1 FROM totp_active WHERE user_id = ?)
		ON CONFLICT(user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret, created_at = excluded.created_at`

	res, err := s.db.ExecContext(ctx, q,
		cred.UserID, cred.ID, cred.Secret, formatTime(cred.CreatedAt), cred.UserID)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: enrolling a pending TOTP credential: %w", err)
	}
	n, err := affected(res, "enrolling a pending TOTP credential")
	if err != nil {
		return err
	}
	if n == 0 {
		return totp.ErrTOTPAlreadyEnrolled
	}
	return nil
}

// ReplacePending is EnrollPending without the active-credential guard: it
// stores cred as userID's pending enrollment whatever else is on file, and
// leaves any active credential completely alone, so codes keep validating
// against the old factor until a later ConfirmEnrollment promotes this one.
func (s *TOTPStore) ReplacePending(ctx context.Context, cred *totp.Credential) error {
	const q = `INSERT INTO totp_pending (user_id, id, secret, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret, created_at = excluded.created_at`

	_, err := s.db.ExecContext(ctx, q,
		cred.UserID, cred.ID, cred.Secret, formatTime(cred.CreatedAt))
	if err != nil {
		return fmt.Errorf("sulis/sqlite: replacing a pending TOTP enrollment: %w", err)
	}
	return nil
}

// ConfirmEnrollment promotes userID's pending enrollment to active, but only
// while it is still the one named by pendingID — the enrollment whose secret
// the caller just matched a code against.
//
// The comparison and the promotion are one transaction whose first statement
// is the DELETE that consumes the pending row:
//
//	DELETE FROM totp_pending WHERE user_id = ? AND id = ? RETURNING ...
//
// Returning no row means pendingID no longer matches — already promoted,
// superseded by a racing enrollment, or never there — so nothing is touched
// and totp.ErrTOTPNotEnrolled comes back, which the caller treats exactly like
// "nothing to confirm".
//
// counter is the time step the code was matched at. When an active credential
// already exists (this is a replacement, not a first enrollment) the promoted
// credential keeps whichever counter is higher, so swapping factors can never
// roll the user's replay-protection clock backwards.
func (s *TOTPStore) ConfirmEnrollment(ctx context.Context, userID, pendingID string, counter uint64) (*totp.Credential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sulis/sqlite: confirming a TOTP enrollment: %w", err)
	}
	defer rollback(tx)

	const consume = `DELETE FROM totp_pending WHERE user_id = ? AND id = ?
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
		return nil, fmt.Errorf("sulis/sqlite: confirming a TOTP enrollment: %w", err)
	}
	if promoted.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}

	var prior int64
	err = tx.QueryRowContext(ctx,
		`SELECT last_used_counter FROM totp_active WHERE user_id = ?`, userID).Scan(&prior)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("sulis/sqlite: reading the prior TOTP counter: %w", err)
	}
	if prior > 0 && uint64(prior) > counter {
		counter = uint64(prior)
	}

	const promote = `INSERT INTO totp_active (user_id, id, secret, last_used_counter, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret,
			last_used_counter = excluded.last_used_counter,
			created_at = excluded.created_at`
	// #nosec G115 -- a TOTP time-step counter is unix-seconds/period; it does
	// not reach 2^63 in any timeline this code outlives.
	if _, err := tx.ExecContext(ctx, promote,
		userID, promoted.ID, promoted.Secret, int64(counter), formatTime(promoted.CreatedAt),
	); err != nil {
		return nil, fmt.Errorf("sulis/sqlite: promoting a TOTP enrollment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sulis/sqlite: committing a TOTP promotion: %w", err)
	}

	promoted.UserID = userID
	promoted.Verified = true
	promoted.LastUsedCounter = counter
	return &promoted, nil
}

// SaveTOTP persists an update to an existing active credential — in practice
// Validate's post-check LastUsedCounter bump — as a single conditional
// upsert:
//
//	INSERT INTO totp_active (...) VALUES (...)
//	    ON CONFLICT(user_id) DO UPDATE SET ...
//	 WHERE totp_active.id <> excluded.id
//	    OR excluded.last_used_counter >= totp_active.last_used_counter
//
// The WHERE on DO UPDATE is the monotonicity guard: a save that would lower
// the counter for the active credential with the same ID matches nothing,
// changes nothing, and is reported as ErrTOTPCounterRegressed rather than
// applied. Of two racing validations only one advances the clock, and the
// loser cannot rewind it.
func (s *TOTPStore) SaveTOTP(ctx context.Context, cred *totp.Credential) error {
	const q = `INSERT INTO totp_active (user_id, id, secret, last_used_counter, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			id = excluded.id, secret = excluded.secret,
			last_used_counter = excluded.last_used_counter,
			created_at = excluded.created_at
		 WHERE totp_active.id <> excluded.id
		    OR excluded.last_used_counter >= totp_active.last_used_counter`

	// #nosec G115 -- see ConfirmEnrollment: the counter is a time step.
	res, err := s.db.ExecContext(ctx, q,
		cred.UserID, cred.ID, cred.Secret, int64(cred.LastUsedCounter), formatTime(cred.CreatedAt))
	if err != nil {
		return fmt.Errorf("sulis/sqlite: saving a TOTP credential: %w", err)
	}
	n, err := affected(res, "saving a TOTP credential")
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTOTPCounterRegressed
	}
	return nil
}

// DeleteTOTP removes userID's active credential and any pending enrollment,
// both inside one transaction. Removing them one after the other would let a
// concurrent ConfirmEnrollment promotion land in the gap, leaving the
// just-promoted credential behind as an active factor the caller believed it
// had removed entirely. Removing nothing is not an error.
func (s *TOTPStore) DeleteTOTP(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: deleting TOTP credentials: %w", err)
	}
	defer rollback(tx)

	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_active WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting an active TOTP credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_pending WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a pending TOTP enrollment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/sqlite: committing a TOTP deletion: %w", err)
	}
	return nil
}
