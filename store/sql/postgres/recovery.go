package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/borfast/sulis/recovery"
)

// RecoveryStore is the PostgreSQL recovery.Store.
//
// A recovery code is a single-use bypass of every other factor, so ConsumeCode's
// lookup and delete are one statement: a store that looks a code up and then
// deletes it lets two concurrent presentations of the same code both succeed —
// one code, two authentications. The composite primary key on
// (user_id, code_hash) also scopes a code to its owner, so presenting someone
// else's code hash matches no row at all.
type RecoveryStore struct {
	db *sql.DB
}

var _ recovery.Store = (*RecoveryStore)(nil)

// ReplaceCodes replaces the user's whole code set inside one transaction, so no
// reader ever sees the old set gone and the new set not yet there. Regenerating
// replaces, never adds: an empty or nil hashes simply clears the set.
//
// The DELETE is the transaction's first statement, so the user's rows are
// locked before anything is inserted and two concurrent replacements for one
// user serialize on it rather than interleaving into a mixed set.
func (s *RecoveryStore) ReplaceCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/postgres: replacing recovery codes: %w", err)
	}
	defer rollback(tx)

	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("sulis/postgres: clearing the previous recovery codes: %w", err)
	}

	const insert = `INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)`
	now := formatTime(time.Now())
	for _, hash := range hashes {
		if _, err := tx.ExecContext(ctx, insert, userID, hash, now); err != nil {
			return fmt.Errorf("sulis/postgres: storing a recovery code: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/postgres: committing a recovery code replacement: %w", err)
	}
	return nil
}

// ConsumeCode deletes the code matching userID and hash, in one statement. Zero
// rows affected — spent, never issued, or issued to somebody else — is
// recovery.ErrCodeNotFound.
func (s *RecoveryStore) ConsumeCode(ctx context.Context, userID, hash string) error {
	const q = `DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2`

	res, err := s.db.ExecContext(ctx, q, userID, hash)
	if err != nil {
		return fmt.Errorf("sulis/postgres: consuming a recovery code: %w", err)
	}
	n, err := affected(res, "consuming a recovery code")
	if err != nil {
		return err
	}
	if n == 0 {
		return recovery.ErrCodeNotFound
	}
	return nil
}

// CountCodes returns how many unused codes the user has left. A user with none
// is not an error: zero is the answer, and it is the answer an application shows
// on a "you have no recovery codes left" screen.
func (s *RecoveryStore) CountCodes(ctx context.Context, userID string) (int, error) {
	const q = `SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1`

	var n int
	if err := s.db.QueryRowContext(ctx, q, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("sulis/postgres: counting recovery codes: %w", err)
	}
	return n, nil
}

// DeleteCodes removes every code for the user. Removing nothing is not an
// error.
func (s *RecoveryStore) DeleteCodes(ctx context.Context, userID string) error {
	const q = `DELETE FROM recovery_codes WHERE user_id = $1`

	if _, err := s.db.ExecContext(ctx, q, userID); err != nil {
		return fmt.Errorf("sulis/postgres: deleting recovery codes: %w", err)
	}
	return nil
}
