package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/borfast/sulis"
)

// TokenStore is the SQLite sulis.TokenStore.
//
// Everything else rests on ConsumeToken's atomicity, which is why that method
// is the only one here with a transaction: a store that reads the row, checks
// used, and then writes hands two callers presenting the same password-reset
// link at the same instant one working reset each.
type TokenStore struct {
	db *sql.DB
}

var _ sulis.TokenStore = (*TokenStore)(nil)

// tokenColumns is the SELECT list every read below shares, in the order
// scanToken reads them.
//
// #nosec G101 -- a list of column names, not a credential
const tokenColumns = `id, user_id, token_hash, purpose, expires_at, created_at,
	used, email, nonce_hash`

// CreateToken inserts token.
func (s *TokenStore) CreateToken(ctx context.Context, token *sulis.Token) error {
	const q = `INSERT INTO tokens (` + tokenColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, q,
		token.ID, token.UserID, token.TokenHash, string(token.Purpose),
		formatTime(token.ExpiresAt), formatTime(token.CreatedAt),
		boolToInt(token.Used), token.Email, token.NonceHash,
	)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: creating a token: %w", err)
	}
	return nil
}

// ConsumeToken finds the unused token matching hash AND purpose and marks it
// used in one statement, returning it:
//
//	UPDATE tokens SET used = 1
//	 WHERE token_hash = ? AND purpose = ? AND used = 0
//	RETURNING ...
//
// Purpose is part of the lookup key rather than something checked afterwards,
// so a two-factor token presented to the password-reset flow matches nothing
// at all — and, because the statement never touches it, that mismatched
// attempt consumes nothing either.
//
// The statement returning no row means one of two things the caller maps to
// different outcomes, so a follow-up existence check in the same transaction
// tells them apart: sulis.ErrTokenAlreadyUsed when the token is there but
// spent, sulis.ErrTokenNotFound when hash+purpose matches nothing.
//
// Expiry is deliberately not part of the predicate. The contract makes this
// method's job "find the unused token and mark it used"; sulis compares
// ExpiresAt itself, on the token this returns, and wants the token burned
// either way.
func (s *TokenStore) ConsumeToken(ctx context.Context, hash string, purpose sulis.TokenPurpose) (*sulis.Token, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sulis/sqlite: consuming a token: %w", err)
	}
	defer rollback(tx)

	const consume = `UPDATE tokens SET used = 1
		WHERE token_hash = ? AND purpose = ? AND used = 0
		RETURNING ` + tokenColumns

	var tok sulis.Token
	err = scanToken(tx.QueryRowContext(ctx, consume, hash, string(purpose)), &tok)
	switch {
	case errors.Is(err, sulis.ErrTokenNotFound):
		// Nothing unused matched. Either it was already consumed, or there is
		// no such token at all.
		var used int
		err := tx.QueryRowContext(ctx,
			`SELECT used FROM tokens WHERE token_hash = ? AND purpose = ?`,
			hash, string(purpose),
		).Scan(&used)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, sulis.ErrTokenNotFound
		case err != nil:
			return nil, fmt.Errorf("sulis/sqlite: consuming a token: %w", err)
		default:
			return nil, sulis.ErrTokenAlreadyUsed
		}
	case err != nil:
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sulis/sqlite: committing a token consumption: %w", err)
	}
	return &tok, nil
}

// DeleteExpiredTokens removes every token whose expiry has passed, spent or
// not.
func (s *TokenStore) DeleteExpiredTokens(ctx context.Context) error {
	const q = `DELETE FROM tokens WHERE expires_at < ?`

	if _, err := s.db.ExecContext(ctx, q, formatTime(time.Now())); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting expired tokens: %w", err)
	}
	return nil
}

// DeleteUserTokens removes every token for the given user and purpose — the
// "invalidate the outstanding reset links" primitive. Deleting zero tokens is
// not an error.
func (s *TokenStore) DeleteUserTokens(ctx context.Context, userID string, purpose sulis.TokenPurpose) error {
	const q = `DELETE FROM tokens WHERE user_id = ? AND purpose = ?`

	if _, err := s.db.ExecContext(ctx, q, userID, string(purpose)); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a user's tokens: %w", err)
	}
	return nil
}

// scanToken reads one row into dst, reporting a missing row as
// sulis.ErrTokenNotFound.
func scanToken(row scanner, dst *sulis.Token) error {
	var (
		purpose              string
		expiresAt, createdAt string
		used                 int64
	)
	err := row.Scan(
		&dst.ID, &dst.UserID, &dst.TokenHash, &purpose, &expiresAt, &createdAt,
		&used, &dst.Email, &dst.NonceHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sulis.ErrTokenNotFound
	}
	if err != nil {
		return fmt.Errorf("sulis/sqlite: reading a token: %w", err)
	}

	if dst.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return err
	}
	if dst.CreatedAt, err = parseTime(createdAt); err != nil {
		return err
	}
	dst.Purpose = sulis.TokenPurpose(purpose)
	dst.Used = used != 0
	return nil
}
