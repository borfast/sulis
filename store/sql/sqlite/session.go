package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/borfast/sulis"
)

// SessionStore is the SQLite sulis.SessionStore.
//
// The requirement worth the most here is DeleteSession's scoping: the
// membership check and the removal are one statement keyed on both columns,
// and zero affected rows is an error rather than a silent success. That is
// what makes cross-user revocation impossible through Sulis.RevokeSession,
// which passes the caller's own user ID — a store that ignored the user ID,
// or reported success when it deleted nothing, would hand anyone who learned
// a session ID the power to sign other people out.
type SessionStore struct {
	db *sql.DB
}

var _ sulis.SessionStore = (*SessionStore)(nil)

// sessionColumns is the SELECT list every read below shares, in the order
// scanSession reads them.
const sessionColumns = `id, user_id, token_hash, expires_at, created_at,
	authenticated_at, method, last_seen_at, idle_expires_at, ip, user_agent, metadata`

// CreateSession inserts session.
func (s *SessionStore) CreateSession(ctx context.Context, session *sulis.Session) error {
	metadata, err := marshalJSON(session.Metadata)
	if err != nil {
		return err
	}

	const q = `INSERT INTO sessions (` + sessionColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, q,
		session.ID, session.UserID, session.TokenHash,
		formatTime(session.ExpiresAt), formatTime(session.CreatedAt),
		formatTime(session.AuthenticatedAt), string(session.Method),
		formatTime(session.LastSeenAt), nullableTime(session.IdleExpiresAt),
		session.IP, session.UserAgent, metadata,
	)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: creating a session: %w", err)
	}
	return nil
}

// GetSessionByTokenHash returns the session with the given token hash, or
// sulis.ErrSessionNotFound. Sessions are only ever looked up by hash; the raw
// token is never stored.
func (s *SessionStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*sulis.Session, error) {
	const q = `SELECT ` + sessionColumns + ` FROM sessions WHERE token_hash = ?`

	var sess sulis.Session
	err := scanSession(s.db.QueryRowContext(ctx, q, tokenHash), &sess)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// ListUserSessions returns every session belonging to userID, in no promised
// order. Matching nothing is not an error.
//
// TokenHash comes back exactly as stored, the same as GetSessionByTokenHash:
// blanking it before an application sees it is Sulis.ListUserSessions's job,
// done once there rather than depended on here.
func (s *SessionStore) ListUserSessions(ctx context.Context, userID string) ([]sulis.Session, error) {
	const q = `SELECT ` + sessionColumns + ` FROM sessions WHERE user_id = ?`

	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("sulis/sqlite: listing a user's sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []sulis.Session
	for rows.Next() {
		var sess sulis.Session
		if err := scanSession(rows, &sess); err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sulis/sqlite: listing a user's sessions: %w", err)
	}
	return sessions, nil
}

// DeleteSession removes the session identified by id if it belongs to userID:
//
//	DELETE FROM sessions WHERE id = ? AND user_id = ?
//
// Zero rows affected — whether id names nothing at all or names someone
// else's session — is sulis.ErrSessionNotFound. The two cases are
// deliberately not distinguished: telling a caller "that session exists but
// is not yours" would answer a question they have no business asking.
func (s *SessionStore) DeleteSession(ctx context.Context, userID, id string) error {
	const q = `DELETE FROM sessions WHERE id = ? AND user_id = ?`

	res, err := s.db.ExecContext(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a session: %w", err)
	}
	n, err := affected(res, "deleting a session")
	if err != nil {
		return err
	}
	if n == 0 {
		return sulis.ErrSessionNotFound
	}
	return nil
}

// DeleteUserSessions removes every session belonging to userID. Matching
// nothing is not an error.
func (s *SessionStore) DeleteUserSessions(ctx context.Context, userID string) error {
	const q = `DELETE FROM sessions WHERE user_id = ?`

	if _, err := s.db.ExecContext(ctx, q, userID); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a user's sessions: %w", err)
	}
	return nil
}

// DeleteUserSessionsExcept removes every session belonging to userID except
// keepSessionID — "sign out everywhere else". keepSessionID naming nothing,
// or naming another user's session, is not an error: every OTHER session for
// userID goes regardless.
func (s *SessionStore) DeleteUserSessionsExcept(ctx context.Context, userID, keepSessionID string) error {
	const q = `DELETE FROM sessions WHERE user_id = ? AND id <> ?`

	if _, err := s.db.ExecContext(ctx, q, userID, keepSessionID); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a user's other sessions: %w", err)
	}
	return nil
}

// CleanExpired removes every session whose absolute expiry has passed. Idle
// expiry is deliberately not swept here: IdleExpiresAt moves forward on every
// throttled touch, ValidateSession enforces it on read, and a session left
// behind by an idle timeout is unusable rather than dangerous.
func (s *SessionStore) CleanExpired(ctx context.Context) error {
	const q = `DELETE FROM sessions WHERE expires_at < ?`

	if _, err := s.db.ExecContext(ctx, q, formatTime(time.Now())); err != nil {
		return fmt.Errorf("sulis/sqlite: cleaning expired sessions: %w", err)
	}
	return nil
}

// UpdateAuthenticatedAt stamps the session identified by id with at, touching
// no other column. Zero rows affected is sulis.ErrSessionNotFound.
//
// This is ReAuthenticate's write path: it refreshes how recently the
// session's owner proved their credential without minting a new session or
// rotating its token.
func (s *SessionStore) UpdateAuthenticatedAt(ctx context.Context, id string, at time.Time) error {
	const q = `UPDATE sessions SET authenticated_at = ? WHERE id = ?`

	res, err := s.db.ExecContext(ctx, q, formatTime(at), id)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: stamping a session's authenticated_at: %w", err)
	}
	n, err := affected(res, "stamping a session's authenticated_at")
	if err != nil {
		return err
	}
	if n == 0 {
		return sulis.ErrSessionNotFound
	}
	return nil
}

// TouchSession stamps the session identified by id with a fresh lastSeen and
// idleExpires, touching no other column. Zero rows affected is
// sulis.ErrSessionNotFound.
//
// A nil idleExpires is written as SQL NULL, clearing whatever was there: an
// application that enables idle expiry and later disables it must not have
// the old deadline linger and quietly start enforcing itself again.
func (s *SessionStore) TouchSession(ctx context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error {
	const q = `UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?`

	res, err := s.db.ExecContext(ctx, q, formatTime(lastSeen), nullableTime(idleExpires), id)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: touching a session: %w", err)
	}
	n, err := affected(res, "touching a session")
	if err != nil {
		return err
	}
	if n == 0 {
		return sulis.ErrSessionNotFound
	}
	return nil
}

// scanner is what *sql.Row and *sql.Rows have in common, so one scan helper
// serves both the single-row reads and ListUserSessions.
type scanner interface {
	Scan(dest ...any) error
}

// scanSession reads one row into dst, allocating everything mutable it holds.
func scanSession(row scanner, dst *sulis.Session) error {
	var (
		expiresAt, createdAt, authenticatedAt, lastSeenAt string
		method                                            string
		idleExpiresAt, metadata                           sql.NullString
	)
	err := row.Scan(
		&dst.ID, &dst.UserID, &dst.TokenHash, &expiresAt, &createdAt,
		&authenticatedAt, &method, &lastSeenAt, &idleExpiresAt,
		&dst.IP, &dst.UserAgent, &metadata,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sulis.ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("sulis/sqlite: reading a session: %w", err)
	}

	if dst.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return err
	}
	if dst.CreatedAt, err = parseTime(createdAt); err != nil {
		return err
	}
	if dst.AuthenticatedAt, err = parseTime(authenticatedAt); err != nil {
		return err
	}
	if dst.LastSeenAt, err = parseTime(lastSeenAt); err != nil {
		return err
	}
	if dst.IdleExpiresAt, err = scanNullableTime(idleExpiresAt); err != nil {
		return err
	}
	if err := unmarshalJSON(metadata, &dst.Metadata); err != nil {
		return err
	}
	dst.Method = sulis.AuthMethod(method)
	return nil
}
